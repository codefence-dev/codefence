"""JavaScript lexer tests."""
from __future__ import annotations

import codefence as cf


def kinds(tokens):
    return [t.kind.value for t in tokens]


def test_empty_source():
    assert cf.tokenize_js("") == []


def test_skips_line_comment():
    tokens = cf.tokenize_js("// hello\nx")
    assert [(t.kind.value, t.value) for t in tokens] == [("ident", "x")]


def test_skips_block_comment():
    tokens = cf.tokenize_js("/* a\nb */ x")
    assert [(t.kind.value, t.value) for t in tokens] == [("ident", "x")]


def test_string_double_quote():
    tokens = cf.tokenize_js('"hello"')
    assert tokens[0].kind.value == "string"
    assert tokens[0].value == '"hello"'


def test_template_literal():
    tokens = cf.tokenize_js("`a ${b} c`")
    assert tokens[0].kind.value == "template"


def test_keyword():
    tokens = cf.tokenize_js("const x = 1;")
    assert tokens[0].kind.value == "keyword"
    assert tokens[0].value == "const"


def test_regex_vs_division():
    # after `=` -> regex
    tokens = cf.tokenize_js("var re = /abc/g;")
    regex_tokens = [t for t in tokens if t.kind.value == "regex"]
    assert regex_tokens
    # after ident -> division
    tokens2 = cf.tokenize_js("var x = a / b;")
    punct_slash = [
        t for t in tokens2 if t.kind.value == "punct" and t.value == "/"
    ]
    assert punct_slash


def test_punctuators():
    tokens = cf.tokenize_js("a === b !== c")
    puncts = [t.value for t in tokens if t.kind.value == "punct"]
    assert "===" in puncts
    assert "!==" in puncts


def test_number():
    tokens = cf.tokenize_js("42")
    assert tokens[0].kind.value == "number"
    assert tokens[0].value == "42"
