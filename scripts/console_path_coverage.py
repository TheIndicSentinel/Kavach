#!/usr/bin/env python3
"""Every operation in docs/openapi.yaml is called by the console, or exempt.

An operation is a method and a path (``POST /v1/agents/{agent_id}/revoke``).
It is *called* when console/src (tests, test helpers and the generated
``openapi.d.ts`` excluded) has a string or template literal for its path that
reaches the API with that method. It is *exempt* when
console/api-coverage-exempt.txt lists it with a reason. The check fails
(exit 1) when an operation is neither, and when an exemption is stale: its
operation is not in the spec, or the console calls it.

Standard library only. The spec is read line by line (no YAML library); the
TypeScript is read with a small lexer, not a compiler (comments and JSX text
are skipped), so the reading is deliberately narrow: anything it does not
recognise counts as *not* called, and a misreading fails the check rather
than passing it. The one looser rule is the placeholder rule below.

How a literal's method is decided, at the place the path is used:

* the first argument of ``request(path, init)`` or ``fetch(path, init)``:
  ``init``'s ``method: "<M>"``, or GET when there is no ``init`` or it has no
  ``method``. A ``method`` that is not a string literal, a spread, or an
  ``init`` that is not an object literal: undecided;
* the first argument of a wrapper: a function declared in console/src whose
  first parameter it passes as the first argument to one of the above (or to
  another wrapper). The wrapper's own call decides the method;
* ``href=`` on an element, and ``location.assign`` / ``location.replace``:
  GET (a top-level navigation);
* a literal that a function returns (a path builder), or that a ``const``
  holds: decided at each place that function or constant is used, by the
  same rules.

Anything else (a route table, a hook with an unknown signature, a type) is
undecided and covers nothing. A use inside a named function counts only if
that function is referenced somewhere else in console/src: an API helper that
nothing calls does not cover its path.

Matching a literal to a spec path: the query and fragment are dropped, then
segment by segment. A ``${...}`` segment matches a ``{param}`` segment. It
matches a literal segment only when it is a bare identifier (as in
``/v1/agents/${encodeURIComponent(id)}/${action}``) and that segment's text
also appears as a whole string literal in console/src (``"revoke"``); the
lexer does not know the identifier's type, so a string used for something
else would also satisfy it. A plain text segment matches the same text, or a
``{param}``; when a path with a literal segment there also matches, only the
more literal paths count.

Usage: python3 scripts/console_path_coverage.py [--root DIR] [--exempt FILE] [--list]
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

# Functions that send a request: the path is argument 0, the init argument 1.
FETCHERS = frozenset({"fetch", "request"})

KEYWORDS = frozenset(
    {
        "if", "for", "while", "switch", "catch", "function", "return", "typeof",
        "new", "await", "yield", "void", "delete", "throw", "case", "do",
        "else", "in", "of", "instanceof", "with", "import", "export", "const",
        "let", "var", "async",
    }
)

# A `/` after one of these starts a regular expression, not a division.
REGEX_AFTER_PUNCT = frozenset("(,=:[!&|?{};+-*%~^")
REGEX_AFTER_WORD = frozenset(
    {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete",
     "void", "throw", "instanceof", "yield", "await"}
)


# --------------------------------------------------------------------------
# The spec
# --------------------------------------------------------------------------


def _strip_key(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def parse_spec(text: str) -> list[tuple[str, str]]:
    """``(METHOD, path)`` for every operation under the top-level ``paths:``."""
    ops: list[tuple[str, str]] = []
    in_paths = False
    path_indent: int | None = None
    method_indent: int | None = None
    current: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent == 0:
            in_paths = re.fullmatch(r"paths:\s*(#.*)?", line) is not None
            current = None
            continue
        if not in_paths:
            continue
        key_match = re.match(r"""("[^"]*"|'[^']*'|[^:#\s][^:#]*?)\s*:(\s|$)""", stripped)
        if not key_match:
            continue
        key = _strip_key(key_match.group(1))
        if path_indent is None:
            path_indent = indent
        if indent == path_indent:
            if not key.startswith("/"):
                raise ValueError(f"unexpected key under paths: {key!r}")
            current = key
            method_indent = None
            continue
        if indent < path_indent:
            raise ValueError(f"unexpected indentation under paths: {raw!r}")
        if current is None:
            continue
        if method_indent is None:
            method_indent = indent
        if indent == method_indent and key in METHODS:
            ops.append((key.upper(), current))
    if not ops:
        raise ValueError("no operations found under paths:")
    if len(set(ops)) != len(ops):
        raise ValueError("an operation is listed twice")
    return ops


# --------------------------------------------------------------------------
# The TypeScript lexer
# --------------------------------------------------------------------------


@dataclass
class Tok:
    kind: str  # "id", "str", "tpl", "punct", "num", "regex"
    value: str  # identifier, punctuation, or a plain string's text
    line: int
    parts: list[tuple[str, str]] = field(default_factory=list)  # tpl: ("text"|"expr", s)


def _skip_regex(src: str, i: int) -> int | None:
    """From a ``/`` that starts a regular expression, the index after it.

    None if the line ends first (then it was a division after all).
    """
    n = len(src)
    j = i + 1
    in_class = False
    while j < n and src[j] != "\n":
        d = src[j]
        if d == "\\":
            j += 2
            continue
        if d == "[":
            in_class = True
        elif d == "]":
            in_class = False
        elif d == "/" and not in_class:
            j += 1
            while j < n and (src[j].isalnum() or src[j] == "_"):
                j += 1
            return j
        j += 1
    return None


def _skip_expr(src: str, i: int) -> int:
    """From just after ``${``, the index of its closing ``}``."""
    depth = 0
    n = len(src)
    prev = "("
    while i < n:
        c = src[i]
        if c in "\"'":
            i = _skip_quoted(src, i)[0]
            prev = "a"
            continue
        if c == "`":
            i = _lex_template(src, i)[0]
            prev = "a"
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == "/" and prev in REGEX_AFTER_PUNCT:
            end = _skip_regex(src, i)
            if end is not None:
                i = end
                prev = "a"
                continue
        if c == "{":
            depth += 1
        elif c == "}":
            if depth == 0:
                return i
            depth -= 1
        if not c.isspace():
            prev = c
        i += 1
    return n


def _skip_quoted(src: str, i: int, multiline: bool = False) -> tuple[int, str]:
    """A '...' or "..." string from its opening quote: the index after it, and its text.

    Outside a JSX attribute, an unclosed string ends at the end of its line,
    so a misreading never runs past one line.
    """
    quote = src[i]
    j = i + 1
    out = []
    n = len(src)
    while j < n:
        c = src[j]
        if c == "\\" and j + 1 < n and not multiline:
            out.append(src[j + 1])
            j += 2
            continue
        if c == quote:
            return j + 1, "".join(out)
        if c == "\n" and not multiline:
            return j, "".join(out)
        out.append(c)
        j += 1
    return n, "".join(out)


def _lex_template(src: str, i: int) -> tuple[int, list[tuple[str, str]]]:
    """A template literal from its backtick: the index after it, and its parts."""
    j = i + 1
    n = len(src)
    parts: list[tuple[str, str]] = []
    text: list[str] = []
    while j < n:
        c = src[j]
        if c == "\\" and j + 1 < n:
            text.append(src[j + 1])
            j += 2
            continue
        if c == "`":
            if text:
                parts.append(("text", "".join(text)))
            return j + 1, parts
        if src.startswith("${", j):
            if text:
                parts.append(("text", "".join(text)))
                text = []
            end = _skip_expr(src, j + 2)
            parts.append(("expr", src[j + 2 : end].strip()))
            j = end + 1
            continue
        text.append(c)
        j += 1
    if text:
        parts.append(("text", "".join(text)))
    return n, parts


# Where a `<` starts a JSX element (in a .tsx file) rather than a comparison
# or type arguments.
JSX_AFTER_PUNCT = frozenset({"(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "=>"})
JSX_AFTER_WORD = frozenset({"return", "yield", "default"})


def lex(src: str, jsx: bool = False) -> list[Tok]:
    """Tokens of TypeScript source, comments dropped.

    With ``jsx``, JSX element text (children) is skipped: only the
    attributes and the ``{...}`` expressions inside elements are tokens.
    """
    toks: list[Tok] = []
    i = 0
    n = len(src)
    line = 1
    # Modes: ["js", open braces] / ["tag", 0] (inside <Name ...>) /
    # ["children", 0] (between an element's tags).
    frames: list[list] = [["js", 0]]

    def emit(kind: str, value: str) -> None:
        toks.append(Tok(kind, value, line))

    while i < n:
        mode = frames[-1][0]
        if mode == "children":
            j = i
            while j < n and src[j] not in "<{":
                j += 1
            line += src.count("\n", i, j)
            i = j
            if i >= n:
                break
            if src[i] == "{":
                emit("punct", "{")
                frames.append(["js", 0])
                i += 1
                continue
            k = i + 1
            while k < n and src[k].isspace():
                k += 1
            if k < n and src[k] == "/":  # a closing tag
                end = src.find(">", k)
                end = n if end < 0 else end + 1
                line += src.count("\n", i, end)
                i = end
                frames.pop()
                continue
            if k < n and src[k] == ">":  # a fragment
                frames.append(["children", 0])
                i = k + 1
                continue
            frames.append(["tag", 0])
            i += 1
            continue

        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            end = n if j < 0 else j + 2
            line += src.count("\n", i, end)
            i = end
            continue

        prev = toks[-1] if toks else None
        if mode == "tag":
            if c == ">":
                frames[-1] = ["children", 0]
                i += 1
                continue
            if src.startswith("/>", i):
                frames.pop()
                i += 2
                continue
            if c == "{":
                emit("punct", "{")
                frames.append(["js", 0])
                i += 1
                continue
            if c in "\"'":
                end, text = _skip_quoted(src, i, multiline=True)
                emit("str", text)
                line += src.count("\n", i, end)
                i = end
                continue
        else:  # js
            if (
                jsx
                and c == "<"
                and i + 1 < n
                and (src[i + 1].isalpha() or src[i + 1] == ">")
                and (
                    prev is None
                    or (prev.kind == "punct" and prev.value in JSX_AFTER_PUNCT)
                    or (prev.kind == "id" and prev.value in JSX_AFTER_WORD)
                )
            ):
                if src[i + 1] == ">":
                    frames.append(["children", 0])
                    i += 2
                else:
                    frames.append(["tag", 0])
                    i += 1
                continue
            if c == "{":
                frames[-1][1] += 1
            elif c == "}":
                if frames[-1][1] == 0 and len(frames) > 1:
                    emit("punct", "}")
                    frames.pop()
                    i += 1
                    continue
                frames[-1][1] -= 1

        if c in "\"'":
            end, text = _skip_quoted(src, i)
            emit("str", text)
            i = end
            continue
        if c == "`":
            end, parts = _lex_template(src, i)
            toks.append(Tok("tpl", "", line, parts))
            line += src.count("\n", i, end)
            i = end
            continue
        if c == "/":
            regex = prev is None or (
                (prev.kind == "punct" and prev.value in REGEX_AFTER_PUNCT)
                or (prev.kind == "id" and prev.value in REGEX_AFTER_WORD)
            )
            end = _skip_regex(src, i) if regex else None
            if end is not None:
                emit("regex", "")
                i = end
                continue
            emit("punct", "/")
            i += 1
            continue
        if c.isalpha() or c in "_$":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            emit("id", src[i:j])
            i = j
            continue
        if c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            emit("num", src[i:j])
            i = j
            continue
        for multi in ("...", "=>"):
            if src.startswith(multi, i):
                emit("punct", multi)
                i += len(multi)
                break
        else:
            emit("punct", c)
            i += 1
    return toks


# --------------------------------------------------------------------------
# One source file, with its bracket structure
# --------------------------------------------------------------------------

OPEN = {"(": ")", "[": "]", "{": "}"}
CLOSE = {v: k for k, v in OPEN.items()}


@dataclass
class Function:
    name: str
    params: list[str]
    body_open: int  # token index of the body's "{"


class Source:
    def __init__(self, name: str, text: str):
        self.name = name
        self.toks = lex(text, jsx=name.endswith(".tsx"))
        n = len(self.toks)
        self.parent: list[int | None] = [None] * n
        self.match: dict[int, int] = {}
        stack: list[int] = []
        for i, t in enumerate(self.toks):
            self.parent[i] = stack[-1] if stack else None
            if t.kind == "punct" and t.value in OPEN:
                stack.append(i)
            elif t.kind == "punct" and t.value in CLOSE:
                # Unbalanced input closes nothing it does not match.
                if stack and self.toks[stack[-1]].value == CLOSE[t.value]:
                    o = stack.pop()
                    self.match[o] = i
                    self.match[i] = o
                    self.parent[i] = stack[-1] if stack else None
        self.functions: dict[int, Function] = {}
        for i, t in enumerate(self.toks):
            if t.kind == "id" and t.value == "function" and i + 2 < n:
                name_tok = self.toks[i + 1]
                paren = i + 2
                if self._is(paren, "<"):  # type parameters: function f<T>(
                    angle = 0
                    while paren < n:
                        if self._is(paren, "<"):
                            angle += 1
                        elif self._is(paren, ">"):
                            angle -= 1
                            if angle == 0:
                                break
                        paren += 1
                    paren += 1
                if name_tok.kind != "id" or not self._is(paren, "("):
                    continue
                close = self.match.get(paren)
                if close is None:
                    continue
                params = self._params(paren, close)
                j = close + 1
                while j < n and not self._is(j, "{") and not self._is(j, ";"):
                    j += 1
                if j < n and self._is(j, "{"):
                    self.functions[j] = Function(name_tok.value, params, j)

        # Tokens of `import ... from "x"` and `export { ... } [from "x"]`.
        self.module_names: set[int] = set()
        for i, t in enumerate(self.toks):
            if t.kind != "id" or self.parent[i] is not None or i + 1 >= n:
                continue
            if t.value == "import" and not self._is(i + 1, "("):
                end = i + 1
                while end < n and self.toks[end].kind != "str":
                    end += 1
                self.module_names.update(range(i, end + 1))
            elif t.value == "export" and (self._is(i + 1, "{") or self._is(i + 1, "*")):
                end = self.match.get(i + 1, i + 1)
                if end + 2 < n and self.toks[end + 1].value == "from":
                    end += 2
                self.module_names.update(range(i, end + 1))

    def _is(self, i: int, value: str) -> bool:
        return 0 <= i < len(self.toks) and self.toks[i].kind == "punct" and self.toks[i].value == value

    def _params(self, open_i: int, close_i: int) -> list[str]:
        params = []
        expect = True
        for k in range(open_i + 1, close_i):
            if self.parent[k] != open_i:
                continue
            t = self.toks[k]
            if expect and t.kind == "id":
                params.append(t.value)
                expect = False
            elif t.kind == "punct" and t.value == ",":
                expect = True
        return params

    def args(self, open_i: int) -> list[tuple[int, int]]:
        """Token ranges [start, end) of the arguments of the call at ``open_i``."""
        close = self.match[open_i]
        out = []
        start = open_i + 1
        for k in range(open_i + 1, close):
            if self.parent[k] == open_i and self._is(k, ","):
                out.append((start, k))
                start = k + 1
        if start < close:
            out.append((start, close))
        return out

    def enclosing_function(self, i: int) -> Function | None:
        p = self.parent[i]
        while p is not None:
            if p in self.functions:
                return self.functions[p]
            p = self.parent[p]
        return None

    def statement_start(self, i: int) -> int:
        j = i - 1
        top = self.parent[i]
        while j >= 0 and j != top:
            t = self.toks[j]
            if t.kind == "punct" and t.value in (";", "}") and self.parent[j] == top:
                break
            if t.kind == "punct" and t.value in (")", "]") and j in self.match:
                j = self.match[j] - 1
                continue
            j -= 1
        return j + 1

    def line(self, i: int) -> int:
        return self.toks[i].line


# --------------------------------------------------------------------------
# Deciding methods
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Use:
    method: str | None  # None: undecided
    file: str
    line: int
    how: str
    reachable: bool = True


class Console:
    def __init__(self, sources: list[Source]):
        self.sources = sources
        self.functions: dict[str, list[tuple[Source, Function]]] = {}
        self._ids: dict[str, list[tuple[Source, int]]] | None = None
        self.string_literals: set[str] = set()
        # Names used inside `${...}`, which the lexer keeps as text: they
        # count as references (reachability), never as call sites.
        self.template_ids: set[str] = set()
        for s in sources:
            for f in s.functions.values():
                self.functions.setdefault(f.name, []).append((s, f))
            for t in s.toks:
                if t.kind == "str":
                    self.string_literals.add(t.value)
                for kind, value in t.parts:
                    if kind == "expr":
                        self.template_ids.update(BARE_IDENT.findall(value))

    # The call whose argument ``i`` is, as (open paren index, callee index).
    def _call_of(self, s: Source, i: int) -> tuple[int, int] | None:
        o = s.parent[i]
        if o is None or not s._is(o, "(") or o == 0:
            return None
        callee = s.toks[o - 1]
        if callee.kind != "id" or callee.value in KEYWORDS:
            return None
        return o, o - 1

    def _arg_index(self, s: Source, open_i: int, i: int) -> int | None:
        for idx, (a, b) in enumerate(s.args(open_i)):
            if a <= i < b:
                return idx if a == i else None  # the path must be the whole argument start
        return None

    def _init_method(self, s: Source, open_i: int) -> str | None:
        args = s.args(open_i)
        if len(args) < 2:
            return "GET"
        a, b = args[1]
        if not s._is(a, "{") or s.match.get(a) != b - 1:
            return None
        method = "GET"
        for k in range(a + 1, b - 1):
            if s.parent[k] != a:
                continue
            t = s.toks[k]
            if s._is(k, "..."):
                return None
            if t.kind == "id" and t.value == "method":
                if s._is(k + 1, ":") and k + 2 < b and s.toks[k + 2].kind == "str" and (
                    s._is(k + 3, ",") or s._is(k + 3, "}")
                ):
                    method = s.toks[k + 2].value.upper()
                else:
                    return None
        return method

    def _wrapper_method(self, name: str, depth: int) -> str | None:
        found: set[str | None] = set()
        for s, f in self.functions.get(name, []):
            if not f.params:
                return None
            first = f.params[0]
            close = s.match.get(f.body_open)
            if close is None:
                return None
            for k in range(f.body_open + 1, close):
                t = s.toks[k]
                if t.kind == "id" and t.value == first and not s._is(k - 1, "."):
                    call = self._call_of(s, k)
                    if call is None:
                        continue
                    found.update(u.method for u in self._call_method(s, k, call, depth + 1))
        if len(found) != 1:
            return None
        return found.pop()

    def _call_method(self, s: Source, i: int, call: tuple[int, int], depth: int) -> list[Use]:
        open_i, callee_i = call
        name = s.toks[callee_i].value
        where = dict(file=s.name, line=s.line(i))
        if self._arg_index(s, open_i, i) != 0:
            return [Use(None, how=f"argument of {name}()", **where)]
        if name in ("assign", "replace") and s._is(callee_i - 1, ".") and callee_i >= 2 and (
            s.toks[callee_i - 2].kind == "id" and s.toks[callee_i - 2].value == "location"
        ):
            return [Use("GET", how=f"location.{name}()", **where)]
        if name in FETCHERS:
            return [Use(self._init_method(s, open_i), how=f"{name}()", **where)]
        if name in self.functions and depth < 8:
            return [Use(self._wrapper_method(name, depth), how=f"{name}()", **where)]
        return [Use(None, how=f"argument of {name}()", **where)]

    def _reachable(self, s: Source, i: int) -> bool:
        f = s.enclosing_function(i)
        if f is None:
            return True
        return bool(self._references(f.name)) or f.name in self.template_ids

    def _references(self, name: str) -> list[tuple[Source, int]]:
        if self._ids is None:
            self._ids = {}
            for s in self.sources:
                for k, t in enumerate(s.toks):
                    if t.kind == "id":
                        self._ids.setdefault(t.value, []).append((s, k))
        refs = []
        for s, k in self._ids.get(name, []):
            before = s.toks[k - 1] if k > 0 else None
            if before is not None and before.kind == "id" and before.value in ("function", "const", "let", "var"):
                continue  # the declaration
            if s._is(k - 1, "."):
                continue  # a member of something else
            if k in s.module_names:
                continue  # an import or export list
            refs.append((s, k))
        return refs

    def uses(self, s: Source, i: int, depth: int = 0) -> list[Use]:
        """How the value at token ``i`` (a path, or a name holding one) is used."""
        where = dict(file=s.name, line=s.line(i))
        if depth > 8:
            return [Use(None, how="too many indirections", **where)]
        reachable = self._reachable(s, i)

        def mark(us: list[Use]) -> list[Use]:
            return [Use(u.method, u.file, u.line, u.how, u.reachable and reachable) for u in us]

        # href="/path" or href={NAME}
        if s._is(i - 1, "=") and i >= 2 and s.toks[i - 2].value == "href":
            return mark([Use("GET", how="href", **where)])
        if s._is(i - 1, "{") and s._is(i - 2, "=") and i >= 3 and s.toks[i - 3].value == "href" and s._is(i + 1, "}"):
            return mark([Use("GET", how="href", **where)])

        call = self._call_of(s, i)
        if call is not None:
            return mark(self._call_method(s, i, call, depth))

        start = s.statement_start(i)
        first = s.toks[start]
        # A path builder: `return <path>` in a named function.
        if first.kind == "id" and first.value == "return":
            f = s.enclosing_function(i)
            if f is not None:
                return self._name_uses(f.name, depth, called=True) or [
                    Use(None, how=f"{f.name}() is never called", **where)
                ]
        # A constant: `[export] const NAME = <path>`.
        k = start + (1 if first.kind == "id" and first.value == "export" else 0)
        if (
            s.toks[k].kind == "id"
            and s.toks[k].value == "const"
            and k + 2 < len(s.toks)
            and s.toks[k + 1].kind == "id"
            and s._is(k + 2, "=")
            and s.parent[i] == s.parent[start]
        ):
            name = s.toks[k + 1].value
            return self._name_uses(name, depth, called=False) or [
                Use(None, how=f"{name} is never used", **where)
            ]
        return mark([Use(None, how="not passed to a request", **where)])

    def _name_uses(self, name: str, depth: int, called: bool) -> list[Use]:
        out: list[Use] = []
        for s, k in self._references(name):
            if called and not s._is(k + 1, "("):
                continue
            out.extend(self.uses(s, k, depth + 1))
        return out


# --------------------------------------------------------------------------
# Matching literals to spec paths
# --------------------------------------------------------------------------

BARE_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
PLAIN_SEGMENT = re.compile(r"[A-Za-z0-9._~%!$&'()*+,;=@-]+")


def literal_segments(tok: Tok) -> list[tuple[str, str]] | None:
    """A path literal as segments ("text", s) / ("expr", e) / ("mixed", ""), or None."""
    parts = [("text", tok.value)] if tok.kind == "str" else tok.parts
    if not parts or parts[0][0] != "text" or not parts[0][1].startswith("/") or parts[0][1].startswith("//"):
        return None
    # Drop the query and the fragment.
    kept: list[tuple[str, str]] = []
    for kind, value in parts:
        if kind == "text":
            cut = re.search(r"[?#]", value)
            if cut:
                if value[: cut.start()]:
                    kept.append((kind, value[: cut.start()]))
                break
        kept.append((kind, value))
    segments: list[list[tuple[str, str]]] = [[]]
    for kind, value in kept:
        if kind == "expr":
            segments[-1].append(("expr", value))
            continue
        pieces = value.split("/")
        for idx, piece in enumerate(pieces):
            if idx > 0:
                segments.append([])
            if piece:
                segments[-1].append(("text", piece))
    segments = segments[1:]  # before the leading "/"
    out: list[tuple[str, str]] = []
    for seg in segments:
        if len(seg) == 1:
            out.append(seg[0])
        elif not seg:
            out.append(("text", ""))
        else:
            out.append(("mixed", ""))
    if out and out[-1] == ("text", ""):
        out.pop()  # a trailing slash
    return out


def matches(segments: list[tuple[str, str]], path: str, strings: set[str]) -> int | None:
    """How many literal spec segments it matched, or None if it does not match."""
    spec = path.strip("/").split("/") if path != "/" else []
    if len(spec) != len(segments):
        return None
    score = 0
    for want, (kind, value) in zip(spec, segments):
        is_param = want.startswith("{") and want.endswith("}")
        if kind == "text":
            if value == want and not is_param:
                score += 1
            elif not (is_param and PLAIN_SEGMENT.fullmatch(value)):
                return None
        elif kind == "expr":
            if is_param:
                continue
            if not (BARE_IDENT.fullmatch(value) and want in strings):
                return None
            score += 1
        else:  # mixed
            if not is_param:
                return None
    return score


# --------------------------------------------------------------------------
# The check
# --------------------------------------------------------------------------

EXEMPT_LINE = re.compile(r"^(GET|PUT|POST|DELETE|OPTIONS|HEAD|PATCH|TRACE)\s+(/\S*)\s+(\S.*)$")


def parse_exempt(text: str) -> tuple[dict[tuple[str, str], str], list[str]]:
    exempt: dict[tuple[str, str], str] = {}
    errors: list[str] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = EXEMPT_LINE.match(line)
        if not m:
            errors.append(f"exempt line {n}: expected 'METHOD /path reason', got {line!r}")
            continue
        key = (m.group(1), m.group(2))
        if key in exempt:
            errors.append(f"exempt line {n}: {key[0]} {key[1]} is listed twice")
        exempt[key] = m.group(3)
    return exempt, errors


def is_scanned(path: Path, src_root: Path) -> bool:
    rel = path.relative_to(src_root)
    if rel.parts and rel.parts[0] == "test":
        return False  # test fixtures and helpers
    name = path.name
    if name.endswith(".d.ts"):
        return False  # declarations (openapi.d.ts names every path)
    if re.search(r"\.test\.tsx?$", name):
        return False
    return name.endswith(".ts") or name.endswith(".tsx")


def coverage(
    spec_text: str, sources: dict[str, str]
) -> dict[tuple[str, str], list[Use]]:
    """For every operation, the uses found in ``sources`` (name -> text)."""
    ops = parse_spec(spec_text)
    console = Console([Source(name, text) for name, text in sorted(sources.items())])
    found: dict[tuple[str, str], list[Use]] = {op: [] for op in ops}
    spec_paths = sorted({p for _, p in ops})
    for s in console.sources:
        for i, t in enumerate(s.toks):
            if t.kind not in ("str", "tpl"):
                continue
            segments = literal_segments(t)
            if segments is None:
                continue
            scored = [(m, p) for p in spec_paths if (m := matches(segments, p, console.string_literals)) is not None]
            if not scored:
                continue
            best = max(m for m, _ in scored)
            paths = [p for m, p in scored if m == best]
            for use in console.uses(s, i):
                for p in paths:
                    if use.method is None or (use.method, p) not in found:
                        # Undecided, or a method the spec does not have here:
                        # recorded against every operation on the path, as a hint.
                        for op in found:
                            if op[1] == p:
                                found[op].append(Use(None, use.file, use.line, use.how + (f" ({use.method})" if use.method else ""), use.reachable))
                        continue
                    found[(use.method, p)].append(use)
    return found


def check(spec_text: str, sources: dict[str, str], exempt_text: str) -> tuple[list[str], list[str]]:
    """(errors, report lines)."""
    found = coverage(spec_text, sources)
    exempt, errors = parse_exempt(exempt_text)
    report: list[str] = []
    for op, uses in found.items():
        called = [u for u in uses if u.method is not None and u.reachable]
        label = f"{op[0]} {op[1]}"
        if op in exempt:
            if called:
                first = called[0]
                errors.append(f"{label}: exempt, but the console calls it ({first.file}:{first.line}); remove the exemption")
            report.append(f"exempt  {label}  -- {exempt[op]}")
        elif called:
            where = ", ".join(sorted({f"{u.file}:{u.line}" for u in called}))
            report.append(f"called  {label}  -- {where}")
        else:
            hints = [u for u in uses if u not in called]
            hint = ""
            if hints:
                hint = "; seen but not counted: " + ", ".join(
                    sorted({f"{u.file}:{u.line} ({u.how}{'' if u.reachable else ', in a function nothing references'})" for u in hints})
                )
            errors.append(f"{label}: not called by console/src and not exempt{hint}")
            report.append(f"MISSING {label}")
    for op in exempt:
        if op not in found:
            errors.append(f"{op[0]} {op[1]}: exempt, but docs/openapi.yaml has no such operation; remove the exemption")
    return errors, report


def load_sources(src_root: Path) -> dict[str, str]:
    out = {}
    for path in sorted(src_root.rglob("*")):
        if path.is_file() and is_scanned(path, src_root):
            out[str(path.relative_to(src_root.parent.parent))] = path.read_text(encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent, help="repository root")
    parser.add_argument("--exempt", type=Path, help="exempt file (default: <root>/console/api-coverage-exempt.txt)")
    parser.add_argument("--list", action="store_true", help="print every operation and how it is covered")
    args = parser.parse_args(argv)
    root: Path = args.root
    spec = (root / "docs" / "openapi.yaml").read_text(encoding="utf-8")
    exempt_path = args.exempt or root / "console" / "api-coverage-exempt.txt"
    exempt = exempt_path.read_text(encoding="utf-8")
    errors, report = check(spec, load_sources(root / "console" / "src"), exempt)
    if args.list:
        print("\n".join(report))
    if errors:
        print("console API path coverage: FAILED", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(
            "Call the operation from console/src, or list it in console/api-coverage-exempt.txt\n"
            "with a reason. How a call is recognised: scripts/console_path_coverage.py.",
            file=sys.stderr,
        )
        return 1
    print(f"console API path coverage: OK ({len(report)} operations; "
          f"{sum(r.startswith('called') for r in report)} called, {sum(r.startswith('exempt') for r in report)} exempt)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
