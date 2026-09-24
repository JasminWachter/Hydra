#!/usr/bin/env python3
"""Generate conservative positive-body variants of the MulVAL rule sets.

The source rule sets are retained unchanged for provenance.  Generated variants:

* expand positive body disjunctions into separate rules;
* omit alternatives containing negation-as-failure (``not/1`` or ``\\+``);
* omit alternatives containing the Prolog cut (``!``); and
* omit range-unsafe alternatives whose named head variables are not body-bound; and
* retain positive equality/disequality filters and other XSB/MulVAL built-ins.

The result is monotonic with respect to added input facts, but remains wrapped in
MulVAL/XSB syntax (``interaction_rule/2``, declarations, and directives).  It is
therefore a positive Datalog-compatible rule core, not a standalone pure-Datalog
serialization.
"""

from __future__ import annotations

import hashlib
import itertools
import re
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]

SOURCE_FILES = (
    Path("MulVAL/kb/web_security_rules.P"),
    Path("MulVAL/kb/full_interaction_rules.P"),
    Path("MulVAL/kb/full_post_exploit_rules.P"),
    Path("interaction_rule_generation/nlp_pipeline/kb/web_security_rules.P"),
    Path("interaction_rule_generation/nlp_pipeline/kb/full_interaction_rules.P"),
)


@dataclass
class Stats:
    source_statements: int = 0
    emitted_statements: int = 0
    expanded_alternatives: int = 0
    omitted_negative_alternatives: int = 0
    omitted_cut_alternatives: int = 0
    omitted_unsafe_alternatives: int = 0


def _split_statements(text: str) -> list[str]:
    """Split Prolog source at top-level full stops while preserving comments."""

    chunks: list[str] = []
    start = 0
    paren = bracket = 0
    quote: str | None = None
    line_comment = block_comment = False
    i = 0

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue

        if ch == "%":
            line_comment = True
        elif ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket -= 1
        elif ch == "." and paren == 0 and bracket == 0:
            chunks.append(text[start : i + 1])
            start = i + 1
        i += 1

    if text[start:].strip():
        chunks.append(text[start:])
    return chunks


def _strip_comments(text: str) -> str:
    out: list[str] = []
    quote: str | None = None
    line_comment = block_comment = False
    i = 0
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if line_comment:
            if ch == "\n":
                line_comment = False
                out.append(ch)
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                if ch == "\n":
                    out.append(ch)
                i += 1
            continue
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "%":
            line_comment = True
        elif ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        else:
            out.append(ch)
            if ch in ("'", '"'):
                quote = ch
        i += 1
    return "".join(out)


def _leading_comments(chunk: str) -> str:
    """Keep the comment block that immediately precedes a statement."""

    lines = chunk.splitlines(keepends=True)
    prefix: list[str] = []
    in_block = False
    for line in lines:
        stripped = line.lstrip()
        if in_block:
            prefix.append(line)
            if "*/" in line:
                in_block = False
            continue
        if not stripped.strip() or stripped.startswith("%"):
            prefix.append(line)
            continue
        if stripped.startswith("/*"):
            prefix.append(line)
            in_block = "*/" not in line
            continue
        break
    return "".join(prefix)


def _balanced_outer_parentheses(expr: str) -> bool:
    if not (expr.startswith("(") and expr.endswith(")")):
        return False
    depth = 0
    quote: str | None = None
    for i, ch in enumerate(expr):
        if quote:
            if ch == "\\":
                continue
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and i != len(expr) - 1:
                return False
    return depth == 0


def _strip_outer_parentheses(expr: str) -> str:
    expr = expr.strip()
    while _balanced_outer_parentheses(expr):
        expr = expr[1:-1].strip()
    return expr


def _split_top_level(expr: str, separator: str) -> list[str]:
    parts: list[str] = []
    start = 0
    paren = bracket = 0
    quote: str | None = None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket -= 1
        elif ch == separator and paren == 0 and bracket == 0:
            parts.append(expr[start:i].strip())
            start = i + 1
        i += 1
    parts.append(expr[start:].strip())
    return parts


def _body_to_dnf(body: str) -> list[list[str]]:
    """Return a positive-expression body as disjunctive normal form."""

    body = _strip_outer_parentheses(body)
    alternatives = _split_top_level(body, ";")
    if len(alternatives) > 1:
        return list(itertools.chain.from_iterable(_body_to_dnf(x) for x in alternatives))

    conjuncts = _split_top_level(body, ",")
    if len(conjuncts) > 1:
        factors = [_body_to_dnf(x) for x in conjuncts]
        return [list(itertools.chain.from_iterable(items)) for items in itertools.product(*factors)]

    return [[body.strip()]]


def _classify_alternative(atoms: list[str]) -> str | None:
    for atom in atoms:
        normalized = _strip_outer_parentheses(atom).strip()
        if normalized == "!":
            return "cut"
        if normalized.startswith("\\+") or re.match(r"^not\s*\(", normalized):
            return "negative"
    return None


def _find_top_level_clause_operator(code: str) -> int:
    paren = bracket = 0
    quote: str | None = None
    i = 0
    while i + 1 < len(code):
        ch = code[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket -= 1
        elif ch == ":" and code[i + 1] == "-" and paren == 0 and bracket == 0:
            return i
        i += 1
    return -1


WRAPPER_RE = re.compile(
    r"^\s*interaction_rule\s*\(\s*\(\s*(?P<head>.+?)\s*:-\s*(?P<body>.+?)\s*\)\s*,"
    r"\s*(?P<desc>rule_desc\s*\(.*\))\s*\)\s*\.\s*$",
    re.DOTALL,
)


VARIABLE_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Z][A-Za-z0-9_]*|_[A-Za-z0-9_]*)")


def _named_variables(text: str) -> set[str]:
    return {
        variable
        for variable in VARIABLE_RE.findall(_mask_quoted_text(text))
        if not variable.startswith("_")
    }


def _positive_alternatives(head: str, body: str, stats: Stats) -> list[list[str]]:
    all_alternatives = _body_to_dnf(body)
    kept: list[list[str]] = []
    for atoms in all_alternatives:
        reason = _classify_alternative(atoms)
        if reason == "negative":
            stats.omitted_negative_alternatives += 1
        elif reason == "cut":
            stats.omitted_cut_alternatives += 1
        elif not _named_variables(head).issubset(_named_variables(",".join(atoms))):
            stats.omitted_unsafe_alternatives += 1
        else:
            kept.append(atoms)
    if len(all_alternatives) > 1:
        stats.expanded_alternatives += len(kept)
    return kept


def _render_wrapper(head: str, atoms: list[str], desc: str) -> str:
    body = ",\n    ".join(atom.strip() for atom in atoms)
    return f"interaction_rule(\n  ({head.strip()} :-\n    {body}),\n  {desc.strip()})."


def _render_clause(head: str, atoms: list[str]) -> str:
    body = ",\n    ".join(atom.strip() for atom in atoms)
    return f"{head.strip()} :-\n    {body}."


def _transform_statement(chunk: str, stats: Stats) -> str:
    stats.source_statements += 1
    prefix = _leading_comments(chunk)
    code = _strip_comments(chunk).strip()
    if not code:
        return chunk

    wrapper = WRAPPER_RE.match(code)
    if wrapper:
        alternatives = _positive_alternatives(wrapper.group("head"), wrapper.group("body"), stats)
        if not alternatives:
            return prefix + "% Omitted from positive variant: rule requires negation-as-failure or cut.\n"
        rendered = [
            _render_wrapper(wrapper.group("head"), atoms, wrapper.group("desc"))
            for atoms in alternatives
        ]
        stats.emitted_statements += len(rendered)
        return prefix + "\n\n".join(rendered) + "\n"

    clause_pos = _find_top_level_clause_operator(code)
    if clause_pos >= 0 and not code.lstrip().startswith(":-"):
        head = code[:clause_pos].strip()
        body = code[clause_pos + 2 :].strip()
        if body.endswith("."):
            body = body[:-1].rstrip()
        alternatives = _positive_alternatives(head, body, stats)
        if not alternatives:
            return prefix + "% Omitted from positive variant: clause requires negation-as-failure or cut.\n"
        rendered = [_render_clause(head, atoms) for atoms in alternatives]
        stats.emitted_statements += len(rendered)
        return prefix + "\n\n".join(rendered) + "\n"

    stats.emitted_statements += 1
    return chunk


def _mask_quoted_text(text: str) -> str:
    """Replace quoted content while keeping executable punctuation visible."""

    out: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and i + 1 < len(text):
                out.extend("  ")
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append(" ")
        else:
            if ch in ("'", '"'):
                quote = ch
                out.append(" ")
            else:
                out.append(ch)
        i += 1
    return "".join(out)


def _validate_positive_text(text: str, output: Path) -> None:
    executable = _mask_quoted_text(_strip_comments(text))
    forbidden = {
        "negation-as-failure (\\+)": re.search(r"\\\+", executable),
        "not/1": re.search(r"\bnot\s*\(", executable),
        "body disjunction (;)": re.search(r";", executable),
        "Prolog cut (!):": re.search(r"(?<![A-Za-z0-9_])!(?![=])", executable),
    }
    failures = [name for name, match in forbidden.items() if match]
    if failures:
        raise ValueError(f"{output}: forbidden constructs remain: {', '.join(failures)}")


def _generated_header(source: Path, digest: str, stats: Stats) -> str:
    return f"""% ====================================================================
% GENERATED POSITIVE-BODY / MONOTONIC VARIANT -- DO NOT EDIT DIRECTLY
% Source: {source.as_posix()}
% Source SHA-256: {digest}
%
% The original file remains authoritative and is retained for provenance.
% This variant expands body disjunctions and conservatively omits branches
% that require negation-as-failure or Prolog cut. Positive equality,
% disequality, list terms, declarations, directives, and MulVAL wrappers are
% retained. Consequently this is an executable MulVAL/XSB monotonic variant,
% not a standalone pure/function-free Datalog serialization.
% Regenerate with: python MulVAL/kb/tools/generate_positive_variants.py
% Emitted statements: {stats.emitted_statements}
% Expanded positive alternatives: {stats.expanded_alternatives}
% Omitted negation-dependent alternatives: {stats.omitted_negative_alternatives}
% Omitted cut-dependent alternatives: {stats.omitted_cut_alternatives}
% Omitted range-unsafe alternatives: {stats.omitted_unsafe_alternatives}
% ====================================================================

"""


def generate(source_rel: Path) -> tuple[Path, Stats]:
    source = REPO_ROOT / source_rel
    output = source.with_name(f"{source.stem}_positive{source.suffix}")
    source_bytes = source.read_bytes()
    digest = hashlib.sha256(source_bytes).hexdigest()
    text = source_bytes.decode("utf-8")
    stats = Stats()
    transformed = "".join(_transform_statement(chunk, stats) for chunk in _split_statements(text))
    generated = _generated_header(source_rel, digest, stats) + transformed.lstrip()
    generated = "\n".join(line.rstrip() for line in generated.splitlines()) + "\n"
    _validate_positive_text(generated, output)
    output.write_text(generated, encoding="utf-8", newline="\n")
    return output, stats


def main() -> None:
    for source in SOURCE_FILES:
        output, stats = generate(source)
        print(
            f"{output.relative_to(REPO_ROOT)}: "
            f"source={stats.source_statements}, emitted={stats.emitted_statements}, "
            f"expanded={stats.expanded_alternatives}, "
            f"omitted_negative={stats.omitted_negative_alternatives}, "
            f"omitted_cut={stats.omitted_cut_alternatives}, "
            f"omitted_unsafe={stats.omitted_unsafe_alternatives}"
        )


if __name__ == "__main__":
    main()
