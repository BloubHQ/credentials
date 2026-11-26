//! Canonical forms checked against libxml2 (`tests/fixtures/xml/c14n-lxml.json`, made by
//! `c14n_lxml.py` over lxml), against the examples of the W3C specifications that libxml2
//! does not reproduce (subtrees), and every refusal.

use super::*;

const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const C14N_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
const C14N11: &str = "http://www.w3.org/2006/12/xml-c14n11";
const C14N11_COMMENTS: &str = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
const EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

fn canon(algorithm: &str, doc: &str) -> String {
    String::from_utf8(
        c14n(algorithm.as_bytes(), doc.as_bytes(), b"", usize::MAX)
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

fn refusal(algorithm: &str, doc: &[u8]) -> &'static str {
    match c14n(algorithm.as_bytes(), doc, b"", usize::MAX) {
        Err(crate::Error::TemplateInvalid { rule }) => rule,
        Err(other) => panic!("refused for another reason: {other}"),
        Ok(_) => panic!("accepted"),
    }
}

/// The canonical form of the subtree at the first child element of the root.
fn subtree(algorithm: &str, doc: &str) -> String {
    let parsed = parse(doc.as_bytes()).unwrap();
    let root = parsed.element(parsed.root).unwrap();
    let apex = root
        .children
        .iter()
        .copied()
        .find(|i| parsed.element(*i).is_some())
        .unwrap();
    let algorithm = Algorithm::parse(algorithm.as_bytes()).unwrap();
    let out = canonical(&parsed, algorithm, b"", Some(apex), usize::MAX).unwrap();
    String::from_utf8(out.to_vec()).unwrap()
}

#[test]
fn matches_libxml2_on_every_fixture() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/xml/c14n-lxml.json")).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 73);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let algorithm = case["algorithm"].as_str().unwrap();
        let prefixes = case["prefixes"].as_str().unwrap();
        let input = case["input"].as_str().unwrap();
        let expected = case["output"].as_str().unwrap();
        let out = c14n(
            algorithm.as_bytes(),
            input.as_bytes(),
            prefixes.as_bytes(),
            usize::MAX,
        )
        .unwrap_or_else(|e| panic!("{name} {algorithm} {prefixes}: {e}"));
        assert_eq!(
            String::from_utf8(out.to_vec()).unwrap(),
            expected,
            "{name} {algorithm} {prefixes}"
        );
        // A canonical form is its own canonical form.
        let again = c14n(algorithm.as_bytes(), &out, prefixes.as_bytes(), usize::MAX).unwrap();
        assert_eq!(again.as_slice(), out.as_slice(), "{name} {algorithm} again");
        // C14N 1.1 differs from 1.0 only in how a subtree inherits xml: attributes, so on a
        // whole document the two agree (C14N 1.1 section 1.2).
        let eleven = match algorithm {
            C14N => Some(C14N11),
            C14N_COMMENTS => Some(C14N11_COMMENTS),
            _ => None,
        };
        if let Some(eleven) = eleven {
            assert_eq!(canon(eleven, input), expected, "{name} {eleven}");
        }
    }
}

/// C14N 1.0 sections 3.1, 3.3 and 3.4, the lines that do not depend on the DTD the engine
/// refuses, as the specification prints them (also in the libxml2 fixture).
#[test]
fn specification_examples() {
    let doc = "<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->\n";
    assert_eq!(
        canon(C14N, doc),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>"
    );
    assert_eq!(
        canon(C14N_COMMENTS, doc),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"
    );
    let e5 = "<e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I'm\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>";
    assert_eq!(
        canon(C14N, e5),
        "<e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I'm\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>"
    );
    assert_eq!(
        canon(C14N, "<text>First line&#x0d;&#10;Second line</text>"),
        "<text>First line&#xD;\nSecond line</text>"
    );
    assert_eq!(
        canon(
            C14N,
            "<compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>"
        ),
        "<compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>"
    );
    assert_eq!(
        canon(
            C14N,
            "<norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>"
        ),
        "<norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>"
    );
}

/// Exclusive XML Canonicalization 1.0 section 2.2: the same subtree in two contexts. Under
/// C14N it takes the namespaces and the xml: attributes of each context; under the exclusive
/// form it is the same in both. libxml2 does not carry `xml:space="retain"` into the second
/// inclusive form; the specification does, and so does the engine.
#[test]
fn exclusive_specification_example() {
    let first = "<n0:local xmlns:n0=\"foo:bar\" xmlns:n3=\"ftp://example.org\">\n  <n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n     <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n  </n1:elem2>\n</n0:local>";
    let second = "<n2:pdu xmlns:n1=\"http://example.com\" xmlns:n2=\"http://foo.example\" xml:lang=\"fr\" xml:space=\"retain\">\n  <n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n     <n3:stuff xmlns:n3=\"ftp://example.org\"/>\n  </n1:elem2>\n</n2:pdu>";
    assert_eq!(
        subtree(C14N, first),
        "<n1:elem2 xmlns:n0=\"foo:bar\" xmlns:n1=\"http://example.net\" xmlns:n3=\"ftp://example.org\" xml:lang=\"en\">\n     <n3:stuff></n3:stuff>\n  </n1:elem2>"
    );
    assert_eq!(
        subtree(C14N, second),
        "<n1:elem2 xmlns:n1=\"http://example.net\" xmlns:n2=\"http://foo.example\" xml:lang=\"en\" xml:space=\"retain\">\n     <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>"
    );
    let exclusive = "<n1:elem2 xmlns:n1=\"http://example.net\" xml:lang=\"en\">\n     <n3:stuff xmlns:n3=\"ftp://example.org\"></n3:stuff>\n  </n1:elem2>";
    assert_eq!(subtree(EXC, first), exclusive);
    assert_eq!(subtree(EXC, second), exclusive);
    // C14N 1.1 inherits xml:lang and xml:space, and refuses the xml:base it would fix up.
    assert_eq!(subtree(C14N11, second), subtree(C14N, second));
    let parsed = parse(b"<a xml:base=\"http://e/x/\"><b/></a>").unwrap();
    let apex = parsed.element(parsed.root).unwrap().children[0];
    let eleven = Algorithm::parse(C14N11.as_bytes()).unwrap();
    assert!(canonical(&parsed, eleven, b"", Some(apex), usize::MAX).is_err());
}

#[test]
fn prefix_lists_and_algorithms() {
    let doc = b"<r xmlns:u=\"urn:u\"><a/></r>";
    let with = |prefixes: &[u8]| c14n(EXC.as_bytes(), doc, prefixes, usize::MAX);
    assert_eq!(
        with(b"u").unwrap().as_slice(),
        b"<r xmlns:u=\"urn:u\"><a></a></r>"
    );
    // A listed prefix that is not in scope renders nothing.
    assert_eq!(with(b"zz").unwrap().as_slice(), b"<r><a></a></r>");
    for bad_list in [&b"#all"[..], b"1x", b"a:b", b"\xff"] {
        assert!(with(bad_list).is_err());
    }
    assert!(c14n(C14N.as_bytes(), doc, b"u", usize::MAX).is_err());
    assert!(
        c14n(
            b"http://www.w3.org/2006/12/xml-c14n11#",
            doc,
            b"",
            usize::MAX
        )
        .is_err()
    );
}

#[test]
fn dtds_and_entities_are_refused() {
    let dtd = "an XML document type declaration (DTDs and entities are refused)";
    // C14N 1.0 section 3.5 (entity references).
    let w3c_35 = b"<!DOCTYPE doc [\n<!ATTLIST doc attrExtEnt ENTITY #IMPLIED>\n<!ENTITY ent1 \"Hello\">\n<!ENTITY ent2 SYSTEM \"world.txt\">\n<!ENTITY entExt SYSTEM \"earth.gif\" NDATA gif>\n<!NOTATION gif SYSTEM \"viewgif.exe\">\n]>\n<doc attrExtEnt=\"entExt\">\n   &ent1;, &ent2;!\n</doc>";
    assert_eq!(refusal(C14N, w3c_35), dtd);
    // An external entity (XXE).
    let xxe = b"<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>";
    assert_eq!(refusal(EXC, xxe), dtd);
    // Billion laughs.
    let mut laughs = String::from("<!DOCTYPE lolz [<!ENTITY lol \"lol\">");
    for i in 1..10 {
        let prev = if i == 1 {
            "lol".to_string()
        } else {
            format!("lol{}", i - 1)
        };
        laughs += &format!("<!ENTITY lol{i} \"{}\">", format!("&{prev};").repeat(10));
    }
    laughs += "]><lolz>&lol9;</lolz>";
    assert_eq!(refusal(EXC, laughs.as_bytes()), dtd);
    // A reference to an entity no DTD declares, in text and in an attribute.
    assert_eq!(
        refusal(EXC, b"<r>&ent1;</r>"),
        "an XML entity reference no DTD declares"
    );
    assert_eq!(
        refusal(EXC, b"<r a=\"&ent1;\"/>"),
        "an XML entity reference no DTD declares"
    );
}

#[test]
fn limits_are_enforced() {
    let nested = |depth: usize| "<a>".repeat(depth) + &"</a>".repeat(depth);
    assert!(
        c14n(
            EXC.as_bytes(),
            nested(MAX_DEPTH).as_bytes(),
            b"",
            usize::MAX
        )
        .is_ok()
    );
    assert_eq!(
        refusal(EXC, nested(MAX_DEPTH + 1).as_bytes()),
        "an XML document nested too deeply"
    );
    // Far deeper than the limit: refused before anything recurses.
    assert_eq!(
        refusal(EXC, nested(100_000).as_bytes()),
        "an XML document nested too deeply"
    );
    let wide = "<r>".to_string() + &"<a/>".repeat(MAX_NODES) + "</r>";
    assert_eq!(
        refusal(EXC, wide.as_bytes()),
        "an XML document with too many nodes"
    );
    let big = "<r>".to_string() + &"x".repeat(MAX_XML) + "</r>";
    assert_eq!(
        refusal(EXC, big.as_bytes()),
        "an XML document over the size limit"
    );
    // The exclusive form repeats a declaration on every element that uses it: 1,000
    // elements under a 1,000-byte name make a 1 MB canonical form from a 7 kB document. The
    // limit given (the budget left) refuses it, as a budget refusal.
    let uri = "urn:".to_string() + &"x".repeat(1000);
    let amplified = format!("<r xmlns:p=\"{uri}\">{}</r>", "<p:a/>".repeat(1000));
    let full = c14n(EXC.as_bytes(), amplified.as_bytes(), b"", usize::MAX).unwrap();
    assert!(full.len() > 1_000_000 && amplified.len() < 8_000);
    assert!(c14n(EXC.as_bytes(), amplified.as_bytes(), b"", full.len()).is_ok());
    assert!(matches!(
        c14n(EXC.as_bytes(), amplified.as_bytes(), b"", full.len() - 1),
        Err(crate::Error::Budget { what: "bytes" })
    ));
}

#[test]
fn malformed_documents_are_refused() {
    for doc in [
        &b"<r/><r/>"[..],
        b"text<r/>",
        b"<r/>text",
        b"<r>",
        b"<r></s>",
        b"</r>",
        b"",
        b"<p:r/>",
        b"<r p:a=\"1\"/>",
        b"<r xmlns:p=\"urn:u\" xmlns:q=\"urn:u\" p:a=\"1\" q:a=\"2\"/>",
        b"<r a=\"1\" a=\"2\"/>",
        b"<r xmlns:p=\"\"/>",
        b"<r xmlns:xml=\"urn:x\"/>",
        b"<r xmlns:x=\"http://www.w3.org/XML/1998/namespace\"/>",
        b"<r xmlns:xmlns=\"urn:x\"/>",
        b"<r xmlns=\"http://www.w3.org/2000/xmlns/\"/>",
        b"<r>\x01</r>",
        b"<r>&#0;</r>",
        b"<r>&#xD800;</r>",
        b"<r>&#x110000;</r>",
        b"<r>]]></r>",
        b"<r a=\"<\"/>",
        b"<r a=\"&amp\"/>",
        b"<r><!-- a -- b --></r>",
        b"<r><!-- a ---></r>",
        b"<r>\xff</r>",
        b"<?xml version=\"1.1\"?><r/>",
        b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r/>",
        b"<r/><?xml version=\"1.0\"?>",
        b"<r><?xml-x?><?XML d?></r>",
        b"<1r/>",
        b"<r:a:b xmlns:r=\"urn:r\"/>",
        b"<r>&</r>",
    ] {
        assert!(
            c14n(EXC.as_bytes(), doc, b"", usize::MAX).is_err(),
            "accepted {}",
            String::from_utf8_lossy(doc)
        );
    }
    // The reserved names used as Namespaces in XML allows.
    assert_eq!(
        canon(
            EXC,
            "<r xmlns:xml=\"http://www.w3.org/XML/1998/namespace\" xml:lang=\"en\"/>"
        ),
        "<r xml:lang=\"en\"></r>"
    );
    // A byte order mark is skipped.
    assert_eq!(canon(EXC, "\u{feff}<r/>"), "<r></r>");
}

#[test]
fn escape_reads_back_in_text_and_attributes() {
    let raw = "a&b<c>d\"e'f\tg\nh\ri \u{e9}";
    let escaped = String::from_utf8(escape(raw.as_bytes()).unwrap().to_vec()).unwrap();
    assert_eq!(
        escaped,
        "a&amp;b&lt;c&gt;d&quot;e&apos;f&#x9;g&#xA;h&#xD;i \u{e9}"
    );
    // Read back: as text, then as an attribute value (whose literal whitespace would have
    // become spaces), each in its canonical escaping.
    assert_eq!(
        canon(EXC, &format!("<r>{escaped}</r>")),
        "<r>a&amp;b&lt;c&gt;d\"e'f\tg\nh&#xD;i \u{e9}</r>"
    );
    assert_eq!(
        canon(EXC, &format!("<r a=\"{escaped}\"/>")),
        "<r a=\"a&amp;b&lt;c>d&quot;e'f&#x9;g&#xA;h&#xD;i \u{e9}\"></r>"
    );
    assert!(escape(b"\x00").is_err());
    assert!(escape(b"\xff").is_err());
    assert!(escape("\u{fffe}".as_bytes()).is_err());
}
