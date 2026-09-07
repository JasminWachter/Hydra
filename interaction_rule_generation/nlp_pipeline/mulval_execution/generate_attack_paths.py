#!/usr/bin/env python3
"""
Simple attack path generator from MulVAL trace_output.P
Outputs a JSON list of attack paths with step-by-step techniques.
"""
import re
import sys
import json
from pathlib import Path

def _split_top_level(text, delimiter=","):
    """Split by delimiter while respecting nested parentheses/brackets and quotes."""
    parts = []
    current = []
    depth_paren = 0
    depth_bracket = 0
    in_quote = False
    quote_char = ""
    escape = False
    for char in text:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\":
            current.append(char)
            escape = True
            continue
        if in_quote:
            current.append(char)
            if char == quote_char:
                in_quote = False
            continue
        if char in ("'", '"'):
            in_quote = True
            quote_char = char
            current.append(char)
            continue
        if char == "(":
            depth_paren += 1
        elif char == ")":
            depth_paren -= 1
        elif char == "[":
            depth_bracket += 1
        elif char == "]":
            depth_bracket -= 1

        if char == delimiter and depth_paren == 0 and depth_bracket == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current).strip())
    return parts


def _parse_trace_term(trace_term):
    """Parse because(...) term into structured tuple."""
    if not trace_term.startswith("because(") or not trace_term.endswith(")"):
        return None
    inner = trace_term[len("because("):-1]
    parts = _split_top_level(inner)
    if len(parts) != 4:
        return None
    rule_id, rule_desc_term, outcome, prerequisites = parts
    try:
        rule_id_int = int(rule_id)
    except ValueError:
        return None
    desc_match = re.search(r"rule_desc\('([^']+)'", rule_desc_term)
    technique = desc_match.group(1) if desc_match else "Unknown technique"
    prereq_raw = prerequisites.strip()
    if prereq_raw.startswith("[") and prereq_raw.endswith("]"):
        prereq_raw = prereq_raw[1:-1]
    return (rule_id_int, technique, outcome.strip(), parse_prerequisites(prereq_raw))


def parse_trace_output(trace_file):
    """Parse trace_output.P and extract attack paths."""
    if not Path(trace_file).exists():
        print(f"Error: Trace file not found: {trace_file}", file=sys.stderr)
        return None, []
    
    try:
        content = Path(trace_file).read_text()
        
        # Extract attack goal
        attack_match = re.search(r'attack\((.*?)\)\.', content)
        attack_goal = attack_match.group(1).strip() if attack_match else "Unknown"
        
        traces = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped.startswith("possible_duplicate_trace_step("):
                continue
            if not stripped.endswith(")."):
                continue
            inner = stripped[len("possible_duplicate_trace_step("):-2]
            parsed = _parse_trace_term(inner)
            if parsed:
                traces.append(parsed)
        
        return attack_goal, traces
    except Exception as e:
        print(f"Error parsing trace file: {e}", file=sys.stderr)
        return None, []

def parse_prerequisites(prerequisites_str):
    """Parse prerequisites string into a list of predicates."""
    prereq_list = []
    if not prerequisites_str.strip():
        return prereq_list
    
    prereq_list = [p for p in _split_top_level(prerequisites_str) if p]
    
    return prereq_list

def generate_attack_paths_json(attack_goal, traces):
    """Generate a simple JSON list of attack paths with step-by-step progression."""
    
    paths = []
    
    for trace_idx, (rule_id, technique, outcome, prereq_list) in enumerate(traces):
        
        # Build the attack path steps
        steps = []
        
        # Step 1-N: Starting predicates (prerequisites)
        for i, prereq in enumerate(prereq_list):
            steps.append({
                "step": i + 1,
                "type": "prerequisite",
                "predicate": prereq
            })
        
        # Final step: Apply technique to reach goal/outcome
        steps.append({
            "step": len(prereq_list) + 1,
            "type": "technique",
            "technique": technique,
            "rule_id": int(rule_id),
            "outcome": outcome
        })
        
        # Create path entry
        path_entry = {
            "path_id": trace_idx,
            "total_steps": len(steps),
            "starting_predicates": prereq_list,
            "goal_predicate": outcome,
            "steps": steps
        }
        
        paths.append(path_entry)
    
    # Create the final JSON structure
    result = {
        "attack_goal": attack_goal,
        "total_paths": len(paths),
        "paths": paths
    }
    
    return result

def main():
    if len(sys.argv) < 2:
        print("Usage: generate_attack_paths.py trace_output.P [output.json]")
        print("If output.json is not specified, outputs to stdout")
        sys.exit(1)
    
    trace_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Parse trace file
    attack_goal, traces = parse_trace_output(trace_file)
    
    if attack_goal is None:
        sys.exit(2)
    
    # Generate JSON
    result = generate_attack_paths_json(attack_goal, traces)
    
    # Output
    json_str = json.dumps(result, indent=2)
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(json_str)
        print(f"Generated attack paths JSON: {output_file}", file=sys.stderr)
        print(f"Total paths: {result['total_paths']}", file=sys.stderr)
    else:
        print(json_str)
    
    sys.exit(0)

if __name__ == "__main__":
    main()
