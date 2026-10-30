"""Tests of umilib.codec.uri: the examples of RFC 3986 and the form encoding of the WHATWG URL Standard,
with Python's urllib.parse as an independent implementation where it follows the same rules."""

import re
import urllib.parse
from pathlib import Path

import pytest

from umilib.codec.uri import URIAuthority, URIError, URIForm, URIHostKind, URIPercent, URIReference

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "vectors"
RFC3986 = (VECTORS / "codec" / "uri" / "rfc3986.txt").read_text(encoding="utf-8")
RFC6749 = (VECTORS / "auth" / "oauth" / "rfc6749.txt").read_text(encoding="utf-8")


def resolution_examples() -> list[tuple[str, str]]:
    start = RFC3986.index("\n5.4.1.  Normal Examples")
    end = RFC3986.index("\n6.  Normalization", start)
    return re.findall(r'^\s+"([^"]*)"\s+=\s+"([^"]*)"', RFC3986[start:end], re.MULTILINE)


def test_resolves_the_examples_of_section_5_4():
    base = URIReference.parse("http://a/b/c/d;p?q")
    examples = resolution_examples()
    assert len(examples) == 42
    for reference, target in examples:
        assert str(URIReference.parse(reference).resolve(base)) == target, reference
        # urllib.parse.urljoin follows RFC 3986 §5.2 too, but takes "http:g" as relative (§5.4.2
        # allows that for backward compatibility; a strict parser does not).
        if reference != "http:g":
            assert urllib.parse.urljoin("http://a/b/c/d;p?q", reference) == target, reference


def test_components_of_section_3():
    reference = URIReference.parse("foo://example.com:8042/over/there?name=ferret#nose")
    assert reference == URIReference(
        scheme="foo",
        authority=URIAuthority(host="example.com", port="8042"),
        path="/over/there",
        query="name=ferret",
        fragment="nose",
    )
    assert str(reference) == "foo://example.com:8042/over/there?name=ferret#nose"
    assert not reference.is_absolute() and not reference.is_relative()
    split = urllib.parse.urlsplit("foo://example.com:8042/over/there?name=ferret#nose")
    assert (split.scheme, split.netloc, split.path, split.query, split.fragment) == ("foo", str(reference.authority), reference.path, reference.query, reference.fragment)
    ldap = URIReference.parse("ldap://[2001:db8::7]/c=GB?objectClass?one")
    assert ldap.authority is not None and ldap.authority.host_kind() is URIHostKind.IPv6
    assert URIAuthority.parse("u@192.0.2.16:80") == URIAuthority(userinfo="u", host="192.0.2.16", port="80")
    assert URIAuthority(host="192.0.2.16").host_kind() is URIHostKind.IPv4
    assert URIAuthority(host="256.0.0.1").host_kind() is URIHostKind.RegName


def test_rejects_what_appendix_a_does_not_allow():
    for text in [":x", "1a:b", "http://a b/", "http://[::1", "http://[1::2::3]/", "http://a:8x/", "http://u@h@x/", "http://a/%4", "http://a/é"]:
        with pytest.raises(URIError):
            URIReference.parse(text)
    with pytest.raises(URIError) as error:
        URIReference.parse("//a").resolve(URIReference.parse("//b"))
    assert error.value.name == "NotAbsolute"
    assert URIAuthority.is_ipv6(b"1:2:3:4:5:6:1.2.3.4") and not URIAuthority.is_ipv6(b"1:2:3:4:5:6:7:1.2.3.4")
    assert URIAuthority.is_ipvfuture(b"v1.x") and not URIAuthority.is_ipvfuture(b"v.x")
    assert URIAuthority.is_ipv4(b"255.255.255.255") and not URIAuthority.is_ipv4(b"01.2.3.4")


def test_check_and_normalize():
    reference = URIReference(scheme="http", authority=URIAuthority(host="h"), path="b")
    with pytest.raises(URIError):
        reference.check()
    reference.path = "/b"
    reference.check()
    # §6.2.2: the two URIs of the example are equivalent.
    a = URIReference.parse("example://a/b/c/%7Bfoo%7D")
    b = URIReference.parse("eXAMPLE://a/./b/../b/%63/%7bfoo%7d")
    assert a.normalize() == b.normalize()
    assert str(URIReference.parse("HTTP://www.EXAMPLE.com:/").normalize()) == "http://www.example.com/"
    assert URIReference.remove_dot_segments("mid/content=5/../6") == "mid/6"
    assert URIReference.merge(URIReference.parse("http://a"), "g") == "/g"
    URIReference.check_scheme("s+-.0")
    with pytest.raises(URIError):
        URIReference.check_scheme("0s")
    assert URIReference.is_path_byte(ord("/")) and not URIReference.is_path_byte(ord("?"))
    assert URIReference.is_query_byte(ord("?")) and not URIReference.is_query_byte(ord("#"))


def test_percent_encoding():
    for byte in range(256):
        assert URIPercent.is_unreserved(byte) == (chr(byte).isascii() and (chr(byte).isalnum() or chr(byte) in "-._~"))
        assert URIPercent.is_sub_delim(byte) == (chr(byte) in "!$&'()*+,;=")
        assert URIPercent.is_gen_delim(byte) == (chr(byte) in ":/?#[]@")
        data = bytes([byte])
        # urllib.parse.quote with no safe characters keeps exactly the unreserved set.
        assert URIPercent.encode_component(data) == urllib.parse.quote(data, safe="")
        assert URIPercent.decode(URIPercent.encode_component(data).encode()) == data
    assert URIPercent.encode(b"a/b", lambda byte: byte == ord("/")) == "%61/%62"
    assert URIPercent.digit(ord("F")) == 15 and URIPercent.digit(ord("g")) is None
    assert URIPercent.decode_text(b"%C3%A9") == "é"
    with pytest.raises(URIError) as error:
        URIPercent.decode_text(b"%FF")
    assert error.value.name == "UTF8"
    with pytest.raises(URIError):
        URIPercent.check(b"%zz")


def test_form_encoding():
    assert "+%25%26%2B%C2%A3%E2%82%AC" in RFC6749
    assert URIForm.encode_text(" %&+£€") == "+%25%26%2B%C2%A3%E2%82%AC"
    assert URIForm.decode(b"+%25%26%2B%C2%A3%E2%82%AC") == " %&+£€"
    body = b"grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb"
    assert URIForm.parse(body) == urllib.parse.parse_qsl(body.decode(), keep_blank_values=True)
    for text in ["&a=1&&b&c==d&e+f=g%2Bh&%zz=%4&=v", "", "a", "=", "%41%4"]:
        assert URIForm.parse(text.encode()) == urllib.parse.parse_qsl(text, keep_blank_values=True), text
    with pytest.raises(URIError):
        URIForm.parse(b"a=%FF")
    pairs = [("a b", "*-._~"), ("é", "")]
    assert URIForm.encode(pairs) == "a+b=*-._%7E&%C3%A9="
    assert URIForm.parse(URIForm.encode(pairs).encode()) == pairs
    assert URIForm.is_kept(ord("*")) and not URIForm.is_kept(ord("~"))
