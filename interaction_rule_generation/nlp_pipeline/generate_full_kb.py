#!/usr/bin/env python3
"""
Generate MulVAL knowledge base from MITRE ATT&CK techniques.

Reads predicates from nlp_inputs/predicates_core.jsonl and interaction rules
from nlp_outputs/*.rule files, then combines them into kb/full_interaction_rules.P
"""

import json
import re
from pathlib import Path
from typing import List, Set, Tuple, Iterable

SCRIPT_DIR = Path(__file__).parent
NLP_INPUTS_DIR = SCRIPT_DIR / "nlp_inputs"
NLP_OUTPUTS_DIR = SCRIPT_DIR / "nlp_outputs"
KB_DIR = SCRIPT_DIR / "kb"
OUTPUT_FILE = KB_DIR / "full_interaction_rules.P"
PREDICATES_CORE_FILE = NLP_INPUTS_DIR / "predicates_core.jsonl"
ADDITIONAL_PREDICATES_FILE = NLP_OUTPUTS_DIR / "additional_predicates_from_llm.P"

RULE_START_RE = re.compile(r'^\s*% ---- RULE LLM START', re.IGNORECASE)
RULE_END_RE = re.compile(r'^\s*% ---- RULE LLM END', re.IGNORECASE)

# Derived heads to expose as MulVAL interaction rules
DERIVED_HEADS = {
    ("exec", 2),
    ("compromise", 2),
    ("priv_escalation", 3),
    ("loot", 3),
    ("exfiltrated", 3),
    ("persistence", 2),
    ("c2_channel", 2),
}

# skip from declaring built-in predicates explicitly
BUILTIN_UTILITY: Set[Tuple[str, int]] = {
    ("member", 2),
    ("append", 3),
    ("reverse", 2),
    ("reverse_acc", 3),
    ("file_extension", 2),
}
SKIP_PREDICATES: Set[str] = {
    "not",      # negation as failure
    "=",        # unification
    ";",        # disjunction (or)
    ",",        # conjunction (and) 
    "!",        # cut
    "true",     # always succeeds
    "fail",     # always fails
}


def read_predicates_from_jsonl(jsonl_file: Path) -> Tuple[List[str], Set[Tuple[str, int]]]:
    """
    Reads predicate definitions from a JSONL file.
    
    Returns:
        A tuple of (predicate_declarations, derived_predicates_set)
    """
    primitives: List[str] = []
    known_primitives: Set[Tuple[str, int]] = set()
    
    if not jsonl_file.exists():
        print(f"Warning: {jsonl_file} not found. Skipping predicate declarations.")
        return primitives, known_primitives
    
    with open(jsonl_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                pred_data = json.loads(line)
                signature = pred_data.get('signature', '')
                name = pred_data.get('name', '')
                arity = pred_data.get('arity', 0)
                
                if signature:
                    # Generate predicate declaration
                    # Format: primitive(predicate_name(...)).
                    args = ', '.join([f'_{i}' for i in range(arity)])
                    declaration = f"primitive({name}({args}))."
                    primitives.append(declaration)
                    known_primitives.add((name, arity))
                    
            except json.JSONDecodeError as e:
                print(f"Warning: Could not parse JSON line in {jsonl_file}: {e}")
                continue
    
    return primitives, known_primitives


def read_additional_predicates(additional_file: Path) -> Tuple[List[str], Set[Tuple[str, int]]]:
    """
    Reads additional primitive predicates from the LLM-generated file.
    
    Returns:
        A tuple of (predicate_declarations_lines, additional_primitives_set)
    """
    declarations: List[str] = []
    additional_primitives: Set[Tuple[str, int]] = set()
    
    if not additional_file.exists():
        print(f"Warning: {additional_file} not found. Skipping additional predicates.")
        return declarations, additional_primitives
    
    primitive_re = re.compile(r'^\s*primitive\(([a-zA-Z_][\w]*)\((.*?)\)\)\s*\.\s*$')
    
    with open(additional_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip().startswith('%') or not line.strip():
                continue
            
            m = primitive_re.match(line)
            if m:
                name = m.group(1)
                args_str = m.group(2).strip()
                
                if not args_str:
                    arity = 0
                else:
                    # count arity by splitting arguments
                    arity = len([a for a in args_str.split(',') if a.strip()])
                
                declarations.append(line.strip())
                additional_primitives.add((name, arity))
    
    return declarations, additional_primitives


def extract_llm_rules_from_file(rule_file: Path) -> tuple[str, dict[str, str]]:
    """
    Extracts the content between RULE LLM START and RULE LLM END markers.
    
    Returns:
        The extracted rule content as a string, or empty string if not found.
    """
    if not rule_file.exists():
        return "", {}
    
    content = rule_file.read_text(encoding='utf-8')
    lines = content.splitlines()
    
    extracted_lines = []
    in_rule_block = False
    meta: dict[str, str] = {}
    
    for line in lines:
        # capture technique metadata from header comments
        if line.strip().startswith('% technique_id:'):
            meta['technique_id'] = line.split(':', 1)[1].strip()
        elif line.strip().startswith('% technique_name:'):
            meta['technique_name'] = line.split(':', 1)[1].strip()

        if RULE_START_RE.match(line):
            in_rule_block = True
            continue
        
        if RULE_END_RE.match(line):
            in_rule_block = False
            break
        
        if in_rule_block:
            extracted_lines.append(line)
    
    return '\n'.join(extracted_lines), meta


def split_clauses(block: str) -> list[str]:
    """
    
    Naively split a Prolog block into clauses ending with a period.
    Keeps multi-line bodies together.
    
    """
    clauses: list[str] = []
    buffer = []
    depth = 0
    in_quote = False
    quote_char = ""
    escape = False

    for raw in block.splitlines():
        line = raw.rstrip()
        if not line or line.strip().startswith('%'):
            continue
        for ch in line:
            buffer.append(ch)
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if in_quote:
                if ch == quote_char:
                    in_quote = False
                continue
            if ch in ("'", '"'):
                in_quote = True
                quote_char = ch
                continue
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            elif ch == '.' and depth == 0:
                clause = ''.join(buffer).strip()
                if clause:
                    clauses.append(clause)
                buffer = []
        if buffer:
            buffer.append(' ')

    trailing = ''.join(buffer).strip()
    if trailing:
        clauses.append(trailing)
    return clauses


HEAD_RE_RULE = re.compile(r"^\s*([a-zA-Z_][\w]*)\s*\((.*)\)\s*:-")
HEAD_RE_FACT = re.compile(r"^\s*([a-zA-Z_][\w]*)\s*\((.*)\)\s*\.")


def head_name_arity(clause: str) -> tuple[str, int] | None:
    """Extract head predicate name and arity from a clause string."""
    m = HEAD_RE_RULE.match(clause)
    if not m:
        m = HEAD_RE_FACT.match(clause)
    if not m:
        return None
    name = m.group(1)
    args = m.group(2).strip()
    if args == "":
        arity = 0
    else:
        # count top-level commas to estimate arity
        arity = 1
        depth = 0
        for ch in args:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            elif ch == ',' and depth == 0:
                arity += 1
    return name, arity


CALL_RE = re.compile(r"([a-zA-Z_][\w]*)\s*\(")


def find_calls(clause: str) -> Iterable[Tuple[str, int]]:
    """Find predicate calls in a clause (head and body). Balances parentheses to get arity."""
    s = clause
    idx = 0
    while True:
        m = CALL_RE.search(s, idx)
        if not m:
            break
        name = m.group(1)
        start = m.end() - 1
        depth = 1
        i = start
        while i + 1 < len(s) and depth > 0:
            i += 1
            ch = s[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
        if depth == 0:
            args_sub = s[start + 1:i].strip()
            if args_sub == "":
                arity = 0
            else:
                arity = 1
                d2 = 0
                for ch2 in args_sub:
                    if ch2 == '(':
                        d2 += 1
                    elif ch2 == ')':
                        d2 -= 1
                    elif ch2 == ',' and d2 == 0:
                        arity += 1
            yield (name, arity)
            idx = i + 1
        else:
            idx = m.end()


def to_interaction_rule(clause: str, label: str, metric: float = 1.0) -> str:
    """Wrap a single Prolog clause in an interaction_rule/2 term.
    Removes trailing period inside the wrapper.
    Uses rule_desc() format for compatibility with MulVAL's attack_graph parser.
    """
    inner = clause.strip()
    if inner.endswith('.'):
        inner = inner[:-1]
        
    return f"interaction_rule( ( {inner} ), rule_desc('{label}', {metric}) )."


def generate_full_kb():
    """Generate the complete knowledge base file."""
    KB_DIR.mkdir(exist_ok=True)
    
    print("Generating knowledge base...")
    print(f"Reading predicates from: {PREDICATES_CORE_FILE}")
    print(f"Reading additional predicates from: {ADDITIONAL_PREDICATES_FILE}")
    print(f"Reading rules from: {NLP_OUTPUTS_DIR}")
    print(f"Output file: {OUTPUT_FILE}")
    
    predicate_declarations, known_primitives = read_predicates_from_jsonl(PREDICATES_CORE_FILE)
    additional_declarations, additional_primitives = read_additional_predicates(ADDITIONAL_PREDICATES_FILE)
    
    all_known_primitives = known_primitives | additional_primitives

    rule_files = sorted(NLP_OUTPUTS_DIR.glob("*.rule"))
    
    all_rules: list[str] = []
    all_wrapped: list[str] = []
    techniques_processed = []
    
    discovered_preds: Set[Tuple[str, int]] = set()
    derived_preds: Set[Tuple[str, int]] = set()
    recursive_preds: Set[Tuple[str, int]] = set()
    
    for rule_file in rule_files:
        technique_id = rule_file.stem
        rule_content, meta = extract_llm_rules_from_file(rule_file)

        if rule_content.strip():
            all_rules.append(f"% --- {technique_id} ---")
            all_rules.append(rule_content)
            all_rules.append("")
            techniques_processed.append(technique_id)

            # Build label
            label = technique_id
            if meta.get('technique_name'):
                label = f"{technique_id} - {meta['technique_name']}"

            # Create interaction_rule wrappers only for derived heads
            for clause in split_clauses(rule_content):
                head = head_name_arity(clause)
                if not head:
                    continue
                
                derived_preds.add(head)
                
                if head in DERIVED_HEADS:
                    all_wrapped.append(to_interaction_rule(clause, label))
                
                body_calls = list(find_calls(clause))
                for call in body_calls:
                    discovered_preds.add(call)
                
                # Detect recursion for later tabling: if head appears in body
                if head and head in body_calls:
                    recursive_preds.add(head)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("% ====================================================================\n")
        f.write("% MulVAL Interaction Rules Knowledge Base\n")
        f.write("% ====================================================================\n\n")
        
        f.write("% Primitive Predicates\n")
        
        for declaration in predicate_declarations:
            f.write(f"{declaration}\n")
        
        if additional_declarations:
            for declaration in additional_declarations:
                f.write(f"{declaration}\n")
        
        # We both declare them as primitive (for type classification) and implement below.
        f.write("primitive(member(_elem,_list)).\n")
        f.write("primitive(file_extension(_file,_ext)).\n")
        
        # Additional core predicates for C2 and network analysis
        f.write("primitive(alert_triggered(_host,_alert_type)).\n")
        f.write("primitive(commonly_used_port(_host,_port)).\n")
        f.write("primitive(encrypted_c2_traffic(_host)).\n")
        f.write("primitive(dga_used_for_c2(_host)).\n")

        f.write("\n")
        
        
        f.write("% Derived Predicates\n")
        f.write("% Derived predicates are inferred from interaction rules\n")
        default_derived = [
            ("exec", 2),
            ("compromise", 2),
            ("priv_escalation", 3),
            ("loot", 3),
            ("exfiltrated", 3),
            ("persistence", 2),
            ("c2_channel", 2),
        ]
        def fmt_sig(n: str, a: int) -> str:
            if a == 0:
                return f"{n}()"
            args = ', '.join([f'_{i}' for i in range(a)])
            return f"{n}({args})"
        
        for n, a in default_derived:
            f.write(f"derived({fmt_sig(n,a)}).\n")
            
        auto_derived: List[Tuple[str, int]] = []
        for n, a in sorted(discovered_preds):
            if (n, a) in all_known_primitives or (n, a) in BUILTIN_UTILITY:
                continue
            if n in SKIP_PREDICATES:
                continue
            auto_derived.append((n, a))
        for n, a in auto_derived:
            f.write(f"derived({fmt_sig(n,a)}).\n")
        f.write("\n")
        
        f.write("% Tabling Predicates\n")
        f.write("% Table directives must appear before any clauses that use them\n")
        f.write(":- table exec/2.\n")
        f.write(":- table compromise/2.\n")
        f.write(":- table priv_escalation/3.\n")
        f.write(":- table loot/3.\n")
        f.write(":- table exfiltrated/3.\n")
        f.write(":- table persistence/2.\n")
        f.write(":- table c2_channel/2.\n")
        # Table auto-discovered derived predicates to prevent infinite loops
        for n, a in auto_derived:
            f.write(f":- table {n}/{a}.\n")
        # Table recursive predicates to prevent infinite loops
        if recursive_preds:
            f.write("\n% Tabling for recursive predicates (prevents infinite loops)\n")
            for name, arity in sorted(recursive_preds):
                if (name, arity) not in [(d[0], d[1]) for d in (default_derived + auto_derived)]:
                    f.write(f":- table {name}/{arity}.\n")
        
        f.write(":- dynamic interaction_rule/2.\n")
        f.write("\n")
        
        f.write("% Utility Predicates\n")
        # Standard member/2 list membership
        f.write("member(X,[X|_]).\n")
        f.write("member(X,[_|T]) :- member(X,T).\n\n")
        # append/3 (list concatenation)
        f.write("append([],L,L).\n")
        f.write("append([H|T],L,[H|R]) :- append(T,L,R).\n\n")
        # reverse/2 using accumulator
        f.write("reverse(L,R) :- reverse_acc(L,[],R).\n")
        f.write("reverse_acc([],Acc,Acc).\n")
        f.write("reverse_acc([H|T],Acc,R) :- reverse_acc(T,[H|Acc],R).\n\n")
        # file_extension(File, Ext): Ext is the substring after the last '.' in atom File
        # Works on character codes to avoid library dependencies
        f.write("file_extension(File,Ext) :- atom(File), atom_codes(File,Cs), ")
        f.write("reverse(Cs,RCs), append(ExtCodes,[46|_],RCs), !, ")
        f.write("reverse(ExtCodes,ExtRev), atom_codes(Ext,ExtRev).\n\n")
        # Compatibility shim: map protocol/2 to protocol/3 facts (must be inside file context)
        f.write("protocol(Host,Proto) :- protocol(Host,Proto,_).\n\n")
        # Additional shims for simplified arities used in rules
        f.write("protocol_in_use(Proto) :- protocol(_,Proto,_).\n")
        f.write("uses_common_port(Host,Port) :- commonly_used_port(Host,Port).\n")
        f.write("encrypted_c2_channel(Host) :- encrypted_c2_traffic(Host).\n")
        f.write("dga_c2_channel(Host) :- dga_used_for_c2(Host).\n\n")
        
        # Interaction Rules (raw content)
        f.write("% Interaction Rules\n")
        
        for rule_block in all_rules:
            f.write(f"{rule_block}\n")

        for wrapped in all_wrapped:
            f.write(f"{wrapped}\n")
    
    print(f"Successfully generated: {OUTPUT_FILE}")
    print(f"  Predicates: {len(predicate_declarations)}")
    print(f"  Techniques: {len(techniques_processed)}")
    print(f"  Tabled: {len(auto_derived) + len(recursive_preds) + 7}")


if __name__ == "__main__":
    generate_full_kb()

