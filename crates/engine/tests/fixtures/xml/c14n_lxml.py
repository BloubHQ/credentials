# Makes c14n-lxml.json: the canonical forms libxml2 (through lxml) gives for the documents
# below, under Canonical XML 1.0 and Exclusive XML Canonicalization 1.0, with and without
# comments, and the exclusive form with InclusiveNamespaces prefix lists. The engine's
# `xml_c14n` is checked against them in `crates/engine/src/primitives/xml/tests.rs`.
#
#   python -I c14n_lxml.py c14n-lxml.json
#
# Measured with lxml 6 over libxml2 2.11.9 (the versions are written into the file). Only
# whole documents: libxml2 does not carry the xml: attributes of the ancestors into a
# subtree under inclusive C14N, as C14N 1.0 section 2.4 says it should (the subtree vectors
# of the specification are in the tests instead).
#
# Provenance only: the tests read c14n-lxml.json and never run Python. lxml is not part of
# this repository's toolchain; it was installed outside it to write the file once.
import json
import sys

from lxml import etree

C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
EXC = "http://www.w3.org/2001/10/xml-exc-c14n#"

DOCS = {
    # C14N 1.0 section 3.1 without its DOCTYPE line (the engine refuses every DTD).
    "w3c-3.1": '<?xml version="1.0"?>\n\n<?xml-stylesheet   href="doc.xsl"\n   type="text/xsl"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->\n',
    # Section 3.2.
    "w3c-3.2": '<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>',
    # Section 3.3 without its DTD (the default attribute of e9 goes with it).
    "w3c-3.3": '<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = "elem3"   id="elem3"   />\n   <e4   name="elem4"   id="elem4"   ></e4>\n   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I\'m"\n      xmlns:b="http://www.ietf.org"\n      xmlns:a="http://www.w3.org"\n      xmlns="http://example.org"/>\n   <e6 xmlns="" xmlns:a="http://www.w3.org">\n      <e7 xmlns="http://www.ietf.org">\n         <e8 xmlns="" xmlns:a="http://www.w3.org">\n            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>',
    # Section 3.4 without its DTD: every attribute is CDATA, so normNames and normId are
    # normalized like norm.
    "w3c-3.4": '<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>"0" && value<"10" ?"valid":"error"]]></compute>\n   <compute expr=\'value>"0" &amp;&amp; value&lt;"10" ?"valid":"error"\'>valid</compute>\n   <norm attr=\' &apos;   &#x20;&#13;&#xa;&#9;   &apos; \'/>\n   <normNames attr=\'   A   &#x20;&#13;&#xa;&#9;   B   \'/>\n   <normId id=\' &apos;   &#x20;&#13;&#xa;&#9;   &apos; \'/>\n</doc>',
    # Section 3.6 with a character reference in place of the ISO-8859-1 declaration.
    "w3c-3.6": "<doc>&#169;</doc>",
    "crlf": '<a\r\n b="x\r\ny">one\r\ntwo\rthree&#13;</a>\r\n',
    "cdata-and-refs": "<a>&lt;&gt;&amp;&quot;&apos;<![CDATA[<>&\"']]>&#x10FFFF;&#233;</a>",
    "attr-escapes": "<a b=\"&#9;&#10;&#13;&quot;&lt;&gt;&amp;'\" c='\"'/>",
    "attr-order": '<r xmlns:z="urn:a" xmlns:y="urn:b"><e z:b="1" y:a="2" b="3" a="4" xml:lang="en"/></r>',
    "unused-namespaces": '<r xmlns:u="urn:unused" xmlns:p="urn:p" xmlns="urn:default"><p:a><b xmlns="" p:x="1"/></p:a><c/></r>',
    "redeclared": '<r xmlns:p="urn:1"><p:a xmlns:p="urn:1"><p:b xmlns:p="urn:2"><c xmlns:p="urn:1"/></p:b></p:a></r>',
    "default-undone": '<r xmlns="urn:d"><a xmlns=""><b xmlns="urn:d"/><c/></a></r>',
    "comments-and-pis": '<!--before--><?before data?><r><!-- inside --><?pi   spaced   data ?>x<?empty?></r><!--after--><?after?>',
    "saml-like": '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="2027-01-15T08:00:00Z" Destination="https://idp.example.com/sso"><saml:Issuer>https://sp.example.com</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/></samlp:AuthnRequest>',
    "xsi-type": '<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Name="mail"><saml:AttributeValue xsi:type="xs:string">a@example.com</saml:AttributeValue></saml:Attribute>',
    "soap": '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><soap:Body wsu:Id="body"><m:GetPrice xmlns:m="urn:example:m" b="2" a="1"/></soap:Body></soap:Envelope>',
    "unicode": '<élément attr="日本" xmlns:α="urn:alpha"><α:x>\U0001F600</α:x></élément>',
}

# Prefix lists tried on top of the plain exclusive form.
PREFIX_LISTS = {
    "unused-namespaces": ["u", "#default", "u #default"],
    "xsi-type": ["xs"],
    "soap": ["wsu"],
}


def canon(text, exclusive, comments, prefixes=None):
    tree = etree.fromstring(text.encode("utf-8")).getroottree()
    return etree.tostring(
        tree,
        method="c14n",
        exclusive=exclusive,
        with_comments=comments,
        inclusive_ns_prefixes=prefixes,
    ).decode("utf-8")


cases = []
for name, text in DOCS.items():
    for exclusive, base in ((False, C14N), (True, EXC)):
        for comments in (False, True):
            algorithm = base + ("WithComments" if exclusive and comments else "#WithComments" if comments else "")
            cases.append({"name": name, "algorithm": algorithm, "prefixes": "", "input": text,
                          "output": canon(text, exclusive, comments)})
    for prefixes in PREFIX_LISTS.get(name, []):
        tokens = prefixes.split()
        cases.append({"name": name, "algorithm": EXC, "prefixes": prefixes, "input": text,
                      "output": canon(text, True, False, tokens)})

with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as f:
    json.dump({"lxml": ".".join(map(str, etree.LXML_VERSION)),
               "libxml2": ".".join(map(str, etree.LIBXML_VERSION)),
               "cases": cases}, f, ensure_ascii=True, indent=0)
    f.write("\n")
print(len(cases))
