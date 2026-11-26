//! XML canonicalization: Canonical XML 1.0 and 1.1 and Exclusive XML Canonicalization 1.0
//! (W3C), with and without comments, and the `InclusiveNamespaces` prefix list of the
//! exclusive form; and escaping text for XML.
//!
//! The document is read by the `quick-xml` tokenizer, which keeps prefixes as written. This
//! module adds what canonicalization needs and the tokenizer leaves to its caller: line ends
//! and attribute values normalized (XML 1.0 sections 2.11 and 3.3.3, every attribute CDATA
//! since there is no DTD), references resolved, namespaces resolved and checked (Namespaces
//! in XML 1.0), and the well-formedness rules the tokenizer does not check (one root, no text
//! outside it, legal characters, unique attributes by expanded name).
//!
//! What is refused, never guessed at:
//!
//! - a document type declaration, so no DTD, no entity of any kind beyond the five
//!   predefined ones, no external entity (XXE) and no entity expansion ("billion laughs");
//! - a document over [`MAX_XML`] bytes, nesting deeper than [`MAX_DEPTH`], more than
//!   [`MAX_NODES`] nodes, or a canonical form over [`MAX_CANONICAL`] bytes or over what the
//!   operation's budget has left (the exclusive form repeats a declaration on every element
//!   that uses it, so a short document can have a long canonical form);
//! - anything but UTF-8, and XML 1.1 documents;
//! - an undeclared prefix, a prefix bound to the empty name, and the reserved `xml` and
//!   `xmlns` names misused.
//!
//! The canonical form is written twice: once to count its length, then into a buffer of
//! exactly that size, so a secret in the document leaves no copy behind a reallocation; the
//! parsed document erases its strings when dropped.

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use zeroize::{Zeroize, Zeroizing};

use super::bad;
use crate::{Error, Result};

/// Longest document, in bytes.
pub const MAX_XML: usize = 1024 * 1024;
/// Deepest nesting of elements.
pub const MAX_DEPTH: usize = 64;
/// Most nodes in one document: elements, attributes, namespace declarations, text pieces,
/// comments and processing instructions.
pub const MAX_NODES: usize = 65_536;
/// Longest canonical form, in bytes.
pub const MAX_CANONICAL: usize = 8 * 1024 * 1024;

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

/// The canonicalization algorithms, named by their W3C identifiers.
const ALGORITHMS: &[(&str, Method, bool)] = &[
    (
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        Method::Inclusive10,
        false,
    ),
    (
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
        Method::Inclusive10,
        true,
    ),
    (
        "http://www.w3.org/2006/12/xml-c14n11",
        Method::Inclusive11,
        false,
    ),
    (
        "http://www.w3.org/2006/12/xml-c14n11#WithComments",
        Method::Inclusive11,
        true,
    ),
    (
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        Method::Exclusive,
        false,
    ),
    (
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
        Method::Exclusive,
        true,
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Inclusive10,
    Inclusive11,
    Exclusive,
}

/// A canonicalization algorithm and whether it keeps comments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Algorithm {
    method: Method,
    comments: bool,
}

impl Algorithm {
    fn parse(uri: &[u8]) -> Result<Self> {
        ALGORITHMS
            .iter()
            .find(|(name, _, _)| name.as_bytes() == uri)
            .map(|&(_, method, comments)| Algorithm { method, comments })
            .ok_or(bad("unknown XML canonicalization algorithm"))
    }
}

struct Attr {
    qname: String,
    prefix_len: usize,
    ns: String,
    value: String,
}

impl Attr {
    fn prefix(&self) -> &str {
        self.qname.get(..self.prefix_len).unwrap_or("")
    }

    fn local(&self) -> &str {
        match self.prefix_len {
            0 => &self.qname,
            n => self.qname.get(n + 1..).unwrap_or(""),
        }
    }
}

struct Element {
    qname: String,
    prefix_len: usize,
    /// The namespace declarations on this element: prefix (empty for the default) and name
    /// (empty for `xmlns=""`).
    decls: Vec<(String, String)>,
    attrs: Vec<Attr>,
    children: Vec<usize>,
    parent: Option<usize>,
}

impl Element {
    fn prefix(&self) -> &str {
        self.qname.get(..self.prefix_len).unwrap_or("")
    }
}

enum Node {
    Element(Element),
    /// Character data, as the pieces it was read in (text, references, CDATA sections), each
    /// allocated once at its final size.
    Text(Vec<String>),
    Comment(String),
    /// A processing instruction: target and data.
    Pi(String, String),
}

/// A parsed document: its nodes, the nodes outside the root element, and the root.
struct Doc {
    nodes: Vec<Node>,
    top: Vec<usize>,
    root: usize,
}

impl Drop for Doc {
    fn drop(&mut self) {
        for node in &mut self.nodes {
            match node {
                Node::Element(e) => {
                    e.qname.zeroize();
                    for (p, u) in &mut e.decls {
                        p.zeroize();
                        u.zeroize();
                    }
                    for a in &mut e.attrs {
                        a.qname.zeroize();
                        a.ns.zeroize();
                        a.value.zeroize();
                    }
                }
                Node::Text(pieces) => pieces.iter_mut().for_each(Zeroize::zeroize),
                Node::Comment(c) => c.zeroize(),
                Node::Pi(t, d) => {
                    t.zeroize();
                    d.zeroize();
                }
            }
        }
    }
}

impl Doc {
    fn element(&self, i: usize) -> Option<&Element> {
        match self.nodes.get(i) {
            Some(Node::Element(e)) => Some(e),
            _ => None,
        }
    }

    /// The name a prefix is bound to at element `i` (the empty prefix is the default
    /// namespace, unbound or `xmlns=""` both give the empty name); `None` when unbound.
    fn lookup(&self, mut i: usize, prefix: &str) -> Option<&str> {
        if prefix == "xml" {
            return Some(XML_NS);
        }
        loop {
            let e = self.element(i)?;
            if let Some((_, uri)) = e.decls.iter().find(|(p, _)| p == prefix) {
                return Some(uri);
            }
            match e.parent {
                Some(p) => i = p,
                None => return prefix.is_empty().then_some(""),
            }
        }
    }

    /// Every namespace in scope at element `i` (nearest declaration of each prefix), the
    /// `xml` prefix left out.
    fn in_scope(&self, i: usize) -> Vec<(&str, &str)> {
        let mut out: Vec<(&str, &str)> = Vec::new();
        let mut at = Some(i);
        while let Some(e) = at.and_then(|i| self.element(i)) {
            for (p, u) in &e.decls {
                if p != "xml" && !out.iter().any(|(q, _)| q == p) {
                    out.push((p, u));
                }
            }
            at = e.parent;
        }
        out
    }
}

/// XML 1.0 `Char`.
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || (c as u32) >= 0xc0 && c != '\u{d7}' && c != '\u{f7}'
}

fn is_name_char(c: char) -> bool {
    is_name_start(c) || c.is_ascii_digit() || matches!(c, '-' | '.' | '\u{b7}')
}

/// An `NCName` of Namespaces in XML (a name without a colon).
fn is_ncname(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(is_name_start) && chars.all(is_name_char)
}

/// Splits a `QName` into the length of its prefix (0 for none); refuses anything else.
fn qname(name: &str) -> Result<usize> {
    match name.split_once(':') {
        None if is_ncname(name) => Ok(0),
        Some((prefix, local)) if is_ncname(prefix) && is_ncname(local) => Ok(prefix.len()),
        _ => Err(bad("an XML name that is not a qualified name")),
    }
}

/// The character of a character reference (`#38`, `#x26`), when it is a legal one.
fn char_ref(body: &str) -> Option<char> {
    let n = if let Some(hex) = body.strip_prefix("#x") {
        (!hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| u32::from_str_radix(hex, 16).ok())??
    } else {
        let dec = body.strip_prefix('#')?;
        (!dec.is_empty() && dec.chars().all(|c| c.is_ascii_digit()))
            .then(|| dec.parse::<u32>().ok())??
    };
    char::from_u32(n).filter(|c| is_xml_char(*c))
}

/// The character a reference stands for: a character reference or one of the five
/// predefined entities. Any other entity would need a DTD to declare it, and is refused.
fn reference(body: &str) -> Result<char> {
    Ok(match body {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "apos" => '\'',
        "quot" => '"',
        b if b.starts_with('#') => char_ref(b).ok_or(bad("an illegal XML character reference"))?,
        _ => return Err(bad("an XML entity reference no DTD declares")),
    })
}

/// An attribute value normalized as XML 1.0 section 3.3.3 says for CDATA: references
/// replaced, each literal whitespace character a space. Never longer than the raw value.
fn attr_value(raw: &str) -> Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(c) = rest.chars().next() {
        rest = rest.get(c.len_utf8()..).unwrap_or("");
        match c {
            '<' => return Err(bad("a '<' in an XML attribute value")),
            '&' => {
                let (body, after) = rest
                    .split_once(';')
                    .ok_or(bad("an unterminated XML reference"))?;
                out.push(reference(body)?);
                rest = after;
            }
            c if is_space(c) => out.push(' '),
            c => out.push(c),
        }
    }
    Ok(out)
}

/// XML 1.0 section 2.11: CR LF and a lone CR become LF.
fn normalize_line_ends(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            out.push('\n');
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn malformed<E>(_: E) -> crate::Error {
    bad("a malformed XML document")
}

struct Parser {
    doc: Doc,
    /// The open elements, outermost first.
    open: Vec<usize>,
    root: Option<usize>,
    count: usize,
}

impl Parser {
    fn count(&mut self, n: usize) -> Result<()> {
        self.count = self.count.saturating_add(n);
        if self.count > MAX_NODES {
            return Err(bad("an XML document with too many nodes"));
        }
        Ok(())
    }

    /// Adds a node under the open element, or at the top.
    fn add(&mut self, node: Node) -> Result<usize> {
        self.count(1)?;
        let i = self.doc.nodes.len();
        self.doc.nodes.push(node);
        match self.open.last().copied() {
            Some(parent) => match self.doc.nodes.get_mut(parent) {
                Some(Node::Element(e)) => e.children.push(i),
                _ => return Err(bad("a malformed XML document")),
            },
            None => self.doc.top.push(i),
        }
        Ok(i)
    }

    /// Appends character data to the text node at the end of the open element.
    fn text(&mut self, piece: String) -> Result<()> {
        let parent = self
            .open
            .last()
            .copied()
            .ok_or(bad("XML character data outside the root element"))?;
        let last = match self.doc.nodes.get(parent) {
            Some(Node::Element(e)) => e.children.last().copied(),
            _ => None,
        };
        if let Some(last) = last
            && matches!(self.doc.nodes.get(last), Some(Node::Text(_)))
        {
            self.count(1)?;
            if let Some(Node::Text(pieces)) = self.doc.nodes.get_mut(last) {
                pieces.push(piece);
            }
            return Ok(());
        }
        self.add(Node::Text(vec![piece])).map(|_| ())
    }

    fn start(&mut self, tag: &BytesStart<'_>) -> Result<()> {
        if self.open.len() >= MAX_DEPTH {
            return Err(bad("an XML document nested too deeply"));
        }
        if self.open.is_empty() && self.root.is_some() {
            return Err(bad("an XML document with more than one root element"));
        }
        let name = tag.name().0.to_owned();
        let prefix_len = qname(&name)?;
        let mut decls = Vec::new();
        let mut raw_attrs = Vec::new();
        for attr in tag.attributes() {
            let attr = attr.map_err(malformed)?;
            let key = attr.key.0;
            let value = attr_value(&attr.value)?;
            if key == "xmlns" {
                if value == XML_NS || value == XMLNS_NS {
                    return Err(bad("a reserved XML namespace bound to the default"));
                }
                decls.push((String::new(), value));
            } else if let Some(prefix) = key.strip_prefix("xmlns:") {
                let reserved = prefix == "xmlns"
                    || (prefix == "xml") != (value == XML_NS)
                    || value == XMLNS_NS;
                if !is_ncname(prefix) || reserved || value.is_empty() {
                    return Err(bad("an XML namespace declaration that is not allowed"));
                }
                decls.push((prefix.to_owned(), value));
            } else {
                raw_attrs.push((key.to_owned(), qname(key)?, value));
            }
        }
        self.count(decls.len() + raw_attrs.len())?;
        let i = self.add(Node::Element(Element {
            qname: name,
            prefix_len,
            decls,
            attrs: Vec::new(),
            children: Vec::new(),
            parent: self.open.last().copied(),
        }))?;
        let prefix = self.doc.element(i).map(Element::prefix).unwrap_or("");
        if !prefix.is_empty() && self.doc.lookup(i, prefix).is_none() {
            return Err(bad("an undeclared XML namespace prefix"));
        }
        let mut attrs = Vec::with_capacity(raw_attrs.len());
        for (qname, prefix_len, value) in raw_attrs {
            let ns = match qname.get(..prefix_len).unwrap_or("") {
                // An attribute without a prefix is in no namespace (Namespaces in XML 1.0
                // section 6.2).
                "" => String::new(),
                p => self
                    .doc
                    .lookup(i, p)
                    .ok_or(bad("an undeclared XML namespace prefix"))?
                    .to_owned(),
            };
            let attr = Attr {
                qname,
                prefix_len,
                ns,
                value,
            };
            if attrs
                .iter()
                .any(|a: &Attr| a.ns == attr.ns && a.local() == attr.local())
            {
                return Err(bad("an XML attribute given twice"));
            }
            attrs.push(attr);
        }
        if let Some(Node::Element(e)) = self.doc.nodes.get_mut(i) {
            e.attrs = attrs;
        }
        if self.open.is_empty() {
            self.root = Some(i);
        }
        self.open.push(i);
        Ok(())
    }
}

/// Parses a document.
fn parse(input: &[u8]) -> Result<Doc> {
    if input.len() > MAX_XML {
        return Err(bad("an XML document over the size limit"));
    }
    let text = core::str::from_utf8(input).map_err(|_| bad("an XML document that is not UTF-8"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let text = normalize_line_ends(text);
    if !text.chars().all(is_xml_char) {
        return Err(bad("an illegal character in an XML document"));
    }
    let mut reader = Reader::from_str(&text);
    let config = reader.config_mut();
    config.check_end_names = true;
    config.check_comments = true;
    config.expand_empty_elements = false;
    config.allow_dangling_amp = false;
    config.allow_unmatched_ends = false;
    config.trim_text(false);
    let mut p = Parser {
        doc: Doc {
            nodes: Vec::new(),
            top: Vec::new(),
            root: 0,
        },
        open: Vec::new(),
        root: None,
        count: 0,
    };
    let mut first = true;
    loop {
        let event = reader.read_event().map_err(malformed)?;
        let was_first = core::mem::replace(&mut first, false);
        match event {
            Event::Decl(decl) => {
                let version = decl.version().map_err(malformed)?;
                let utf8 = match decl.encoding() {
                    None => true,
                    Some(e) => e.map_err(malformed)?.eq_ignore_ascii_case("utf-8"),
                };
                if !was_first || &*version != "1.0" || !utf8 {
                    return Err(bad("an XML declaration other than version 1.0 in UTF-8"));
                }
            }
            Event::DocType(_) => {
                return Err(bad(
                    "an XML document type declaration (DTDs and entities are refused)",
                ));
            }
            Event::Start(tag) => p.start(&tag)?,
            Event::Empty(tag) => {
                p.start(&tag)?;
                p.open.pop();
            }
            Event::End(_) => {
                p.open.pop().ok_or(bad("a malformed XML document"))?;
            }
            Event::Text(t) => {
                if p.open.is_empty() {
                    if !t.chars().all(is_space) {
                        return Err(bad("XML character data outside the root element"));
                    }
                } else {
                    if t.contains("]]>") {
                        return Err(bad("']]>' in XML character data"));
                    }
                    p.text(t.to_string())?;
                }
            }
            Event::GeneralRef(r) => {
                let c = reference(&r)?;
                p.text(c.to_string())?;
            }
            Event::CData(c) => p.text(c.to_string())?,
            Event::Comment(c) => {
                if c.ends_with('-') {
                    return Err(bad("a malformed XML comment"));
                }
                p.add(Node::Comment(c.to_string()))?;
            }
            Event::PI(pi) => {
                let target = pi.target();
                if !is_ncname(target) || target.eq_ignore_ascii_case("xml") {
                    return Err(bad("an XML processing instruction with a reserved target"));
                }
                let data = pi.content().trim_start_matches(is_space);
                p.add(Node::Pi(target.to_owned(), data.to_owned()))?;
            }
            Event::Eof => break,
        }
    }
    if !p.open.is_empty() {
        return Err(bad("an XML element left open"));
    }
    p.doc.root = p
        .root
        .ok_or(bad("an XML document without a root element"))?;
    Ok(p.doc)
}

/// A namespace binding: its prefix (empty for the default namespace) and its name.
type Binding<'d> = (&'d str, &'d str);

/// Where the canonical form goes: counted on the first pass, written on the second.
struct Sink<'o> {
    out: Option<&'o mut Vec<u8>>,
    len: usize,
    limit: usize,
}

impl Sink<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.len = self.len.saturating_add(bytes.len());
        if self.len > self.limit {
            // Below the cap, the limit is what the operation's budget has left.
            if self.limit < MAX_CANONICAL {
                return Err(Error::Budget { what: "bytes" });
            }
            return Err(bad("a canonical XML form over the size limit"));
        }
        if let Some(out) = self.out.as_deref_mut() {
            out.extend_from_slice(bytes);
        }
        Ok(())
    }

    fn str(&mut self, s: &str) -> Result<()> {
        self.put(s.as_bytes())
    }

    /// Text content: `&`, `<`, `>` and CR escaped (C14N 1.0 section 2.3).
    fn text(&mut self, s: &str) -> Result<()> {
        self.escaped(s, |c| match c {
            '&' => Some("&amp;"),
            '<' => Some("&lt;"),
            '>' => Some("&gt;"),
            '\r' => Some("&#xD;"),
            _ => None,
        })
    }

    /// An attribute value: `&`, `<`, `"`, TAB, LF and CR escaped.
    fn attr(&mut self, s: &str) -> Result<()> {
        self.escaped(s, |c| match c {
            '&' => Some("&amp;"),
            '<' => Some("&lt;"),
            '"' => Some("&quot;"),
            '\t' => Some("&#x9;"),
            '\n' => Some("&#xA;"),
            '\r' => Some("&#xD;"),
            _ => None,
        })
    }

    fn escaped(&mut self, s: &str, escape: impl Fn(char) -> Option<&'static str>) -> Result<()> {
        let mut start = 0;
        for (at, c) in s.char_indices() {
            if let Some(e) = escape(c) {
                self.str(s.get(start..at).unwrap_or(""))?;
                self.str(e)?;
                start = at + c.len_utf8();
            }
        }
        self.str(s.get(start..).unwrap_or(""))
    }
}

struct Canon<'d> {
    doc: &'d Doc,
    algorithm: Algorithm,
    /// The `InclusiveNamespaces` prefix list of the exclusive form (empty for the default).
    inclusive: Vec<&'d str>,
    apex: usize,
}

impl<'d> Canon<'d> {
    fn document(&self, sink: &mut Sink<'_>) -> Result<()> {
        if self.apex != self.doc.root {
            return self.element(self.apex, &[], sink);
        }
        let mut after = false;
        for &i in &self.doc.top {
            if i == self.doc.root {
                self.element(i, &[], sink)?;
                after = true;
                continue;
            }
            let shown = match self.doc.nodes.get(i) {
                Some(Node::Comment(_)) => self.algorithm.comments,
                Some(Node::Pi(..)) => true,
                _ => false,
            };
            if shown {
                // C14N 1.0 section 2.1: a line feed after each node before the root element,
                // before each node after it.
                if after {
                    sink.str("\n")?;
                }
                self.leaf(i, sink)?;
                if !after {
                    sink.str("\n")?;
                }
            }
        }
        Ok(())
    }

    fn leaf(&self, i: usize, sink: &mut Sink<'_>) -> Result<()> {
        match self.doc.nodes.get(i) {
            Some(Node::Text(pieces)) => pieces.iter().try_for_each(|p| sink.text(p)),
            Some(Node::Comment(c)) if self.algorithm.comments => {
                sink.str("<!--")?;
                sink.str(c)?;
                sink.str("-->")
            }
            Some(Node::Pi(target, data)) => {
                sink.str("<?")?;
                sink.str(target)?;
                if !data.is_empty() {
                    sink.str(" ")?;
                    sink.str(data)?;
                }
                sink.str("?>")
            }
            _ => Ok(()),
        }
    }

    /// The namespace declarations element `i` renders, given those its output ancestors
    /// rendered (`rendered`), and the context its children see.
    fn namespaces(
        &self,
        i: usize,
        e: &'d Element,
        rendered: &[Binding<'d>],
    ) -> (Vec<Binding<'d>>, Vec<Binding<'d>>) {
        let mut context = rendered.to_vec();
        let mut out = Vec::new();
        let candidates: Vec<(&'d str, &'d str)> = match self.algorithm.method {
            Method::Inclusive10 | Method::Inclusive11 => self.doc.in_scope(i),
            Method::Exclusive => {
                // Visibly utilized: the element's own prefix (the default namespace when it
                // has none) and the prefixes of its attributes; then the prefix list.
                let mut prefixes: Vec<&'d str> = vec![e.prefix()];
                prefixes.extend(e.attrs.iter().map(Attr::prefix).filter(|p| !p.is_empty()));
                prefixes.extend(self.inclusive.iter().copied());
                let mut out: Vec<(&'d str, &'d str)> = Vec::new();
                for p in prefixes {
                    if p == "xml" || out.iter().any(|(q, _)| *q == p) {
                        continue;
                    }
                    if let Some(u) = self.doc.lookup(i, p) {
                        out.push((p, u));
                    }
                }
                out
            }
        };
        for (p, u) in candidates {
            let current = context.iter().find(|(q, _)| *q == p).map(|(_, v)| *v);
            let render = if p.is_empty() && u.is_empty() {
                // `xmlns=""` only undoes a default an output ancestor rendered.
                current.is_some_and(|v| !v.is_empty())
            } else {
                current != Some(u)
            };
            if render {
                context.retain(|(q, _)| *q != p);
                context.push((p, u));
                out.push((p, u));
            }
        }
        out.sort_by(|a, b| a.0.cmp(b.0));
        (out, context)
    }

    /// The `xml:` attributes an apex that is not the root inherits from its ancestors under
    /// the inclusive forms (C14N 1.0 section 2.4; C14N 1.1 section 2.4 keeps `xml:lang` and
    /// `xml:space` and fixes `xml:base` up, which is not implemented: refused).
    fn inherited(&self, i: usize, e: &'d Element) -> Result<Vec<&'d Attr>> {
        let mut out: Vec<&'d Attr> = Vec::new();
        if i != self.apex || i == self.doc.root || self.algorithm.method == Method::Exclusive {
            return Ok(out);
        }
        let mut at = e.parent;
        while let Some(a) = at.and_then(|i| self.doc.element(i)) {
            for attr in a.attrs.iter().filter(|x| x.ns == XML_NS) {
                let local = attr.local();
                if self.algorithm.method == Method::Inclusive11 {
                    match local {
                        "base" => {
                            return Err(bad(
                                "C14N 1.1 of a subtree under xml:base is not implemented",
                            ));
                        }
                        "lang" | "space" => {}
                        _ => continue,
                    }
                }
                let present = e.attrs.iter().any(|x| x.ns == XML_NS && x.local() == local)
                    || out.iter().any(|x| x.local() == local);
                if !present {
                    out.push(attr);
                }
            }
            at = a.parent;
        }
        Ok(out)
    }

    fn element(
        &self,
        i: usize,
        rendered: &[(&'d str, &'d str)],
        sink: &mut Sink<'_>,
    ) -> Result<()> {
        let e = self.doc.element(i).ok_or(bad("a malformed XML document"))?;
        let (decls, context) = self.namespaces(i, e, rendered);
        let mut attrs: Vec<&Attr> = e.attrs.iter().collect();
        attrs.extend(self.inherited(i, e)?);
        // Attributes sorted by namespace name, then local name (C14N 1.0 section 2.2); one
        // without a prefix has the empty namespace name and comes first.
        attrs.sort_by(|a, b| (a.ns.as_str(), a.local()).cmp(&(b.ns.as_str(), b.local())));
        sink.str("<")?;
        sink.str(&e.qname)?;
        for (p, u) in decls {
            sink.str(if p.is_empty() { " xmlns" } else { " xmlns:" })?;
            sink.str(p)?;
            sink.str("=\"")?;
            sink.attr(u)?;
            sink.str("\"")?;
        }
        for a in attrs {
            sink.str(" ")?;
            sink.str(&a.qname)?;
            sink.str("=\"")?;
            sink.attr(&a.value)?;
            sink.str("\"")?;
        }
        sink.str(">")?;
        for &child in &e.children {
            match self.doc.nodes.get(child) {
                Some(Node::Element(_)) => self.element(child, &context, sink)?,
                _ => self.leaf(child, sink)?,
            }
        }
        sink.str("</")?;
        sink.str(&e.qname)?;
        sink.str(">")
    }
}

/// The canonical form of `doc` (or of the subtree at `apex`), at most `limit` bytes.
fn canonical(
    doc: &Doc,
    algorithm: Algorithm,
    prefixes: &[u8],
    apex: Option<usize>,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let list =
        core::str::from_utf8(prefixes).map_err(|_| bad("an invalid inclusive prefix list"))?;
    let mut inclusive = Vec::new();
    for token in list.split(is_space).filter(|t| !t.is_empty()) {
        inclusive.push(match token {
            "#default" => "",
            t if is_ncname(t) => t,
            _ => return Err(bad("an invalid inclusive prefix list")),
        });
    }
    if !inclusive.is_empty() && algorithm.method != Method::Exclusive {
        return Err(bad(
            "an inclusive prefix list belongs to exclusive canonicalization",
        ));
    }
    let canon = Canon {
        doc,
        algorithm,
        inclusive,
        apex: apex.unwrap_or(doc.root),
    };
    let limit = limit.min(MAX_CANONICAL);
    let mut count = Sink {
        out: None,
        len: 0,
        limit,
    };
    canon.document(&mut count)?;
    let mut out = Zeroizing::new(Vec::with_capacity(count.len));
    let mut sink = Sink {
        out: Some(&mut out),
        len: 0,
        limit,
    };
    canon.document(&mut sink)?;
    Ok(out)
}

/// `xml_c14n(algorithm, document[, inclusive_prefixes])`: the canonical form of a whole
/// document, at most `limit` bytes (what the budget has left).
pub fn c14n(
    algorithm: &[u8],
    document: &[u8],
    prefixes: &[u8],
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let algorithm = Algorithm::parse(algorithm)?;
    let doc = parse(document)?;
    canonical(&doc, algorithm, prefixes, None, limit)
}

/// `xml_escape(text)`: text written so it reads back the same in XML character data and in
/// an attribute value: `& < > " '` as the predefined entities, TAB, LF and CR as character
/// references (an attribute value would turn them into spaces). Refuses bytes that are not
/// UTF-8 or not XML characters, which no XML document can carry.
pub fn escape(text: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let text =
        core::str::from_utf8(text).map_err(|_| bad("xml_escape of bytes that are not UTF-8"))?;
    if !text.chars().all(is_xml_char) {
        return Err(bad("xml_escape of a character XML cannot carry"));
    }
    let len = text
        .chars()
        .map(|c| match c {
            '&' | '\'' | '"' => 5 + usize::from(c != '&'),
            '<' | '>' => 4,
            '\t' | '\n' | '\r' => 5,
            c => c.len_utf8(),
        })
        .sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let mut buf = [0u8; 4];
    for c in text.chars() {
        out.extend_from_slice(match c {
            '&' => b"&amp;",
            '<' => b"&lt;",
            '>' => b"&gt;",
            '"' => b"&quot;",
            '\'' => b"&apos;",
            '\t' => b"&#x9;",
            '\n' => b"&#xA;",
            '\r' => b"&#xD;",
            c => c.encode_utf8(&mut buf).as_bytes(),
        });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests;
