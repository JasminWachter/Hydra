#!/usr/bin/env python3
"""Trace normalization and parsing component."""

import json
import re
import sys
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class TraceProcessor:
    """Normalizes/parses MulVAL traces and writes JSON attack paths."""

    @staticmethod
    def split_prolog_terms(s: str) -> List[str]:
        terms: List[str] = []
        depth = 0
        current: List[str] = []
        in_quote = False

        for char in s:
            if char == "'" and not in_quote:
                in_quote = True
                current.append(char)
            elif char == "'" and in_quote:
                in_quote = False
                current.append(char)
            elif in_quote:
                current.append(char)
            elif char in ('(', '['):
                depth += 1
                current.append(char)
            elif char in (')', ']'):
                depth -= 1
                current.append(char)
            elif char == ',' and depth == 0:
                term = ''.join(current).strip()
                if term:
                    terms.append(term)
                current = []
            else:
                current.append(char)

        last = ''.join(current).strip()
        if last:
            terms.append(last)
        return terms

    def normalize_trace_output(self, trace_file: Path) -> bool:
        try:
            lines = trace_file.read_text(encoding='utf-8', errors='replace').splitlines()
            normalized_terms: List[str] = []
            buffer = ""

            for raw in lines:
                line = raw.strip()
                if not line:
                    continue

                buffer += line
                if line.endswith('.'):
                    normalized_terms.append(buffer)
                    buffer = ""

            if buffer:
                normalized_terms.append(buffer)

            if not normalized_terms:
                return False

            trace_file.write_text("\n".join(normalized_terms) + "\n", encoding='utf-8')
            return True
        except Exception as error:
            print(f"    ✗ Trace normalization error: {error}", file=sys.stderr)
            return False

    def prepare_attack_graph_trace(self, trace_file: Path, output_dir: Path) -> Optional[Path]:
        try:
            raw_lines = trace_file.read_text(encoding='utf-8', errors='replace').splitlines()

            terms: List[str] = []
            buffer = ""
            for raw in raw_lines:
                line = raw.strip()
                if not line:
                    continue
                buffer += line
                if line.endswith('.'):
                    terms.append(buffer)
                    buffer = ""
            if buffer:
                terms.append(buffer)

            def sanitize_desc(desc_text: str) -> str:
                safe = re.sub(r"[^A-Za-z0-9_./+\- ]+", " ", desc_text)
                return re.sub(r"\s+", " ", safe).strip()

            cleaned_terms: List[str] = []
            for term in terms:
                if not term.startswith('possible_duplicate_trace_step(because('):
                    cleaned_terms.append(term.replace("''", "empty"))
                    continue

                if not term.endswith(')).'):
                    continue

                inner = term[len('possible_duplicate_trace_step('):-2]
                if not inner.startswith('because(') or not inner.endswith(')'):
                    continue

                because_inner = inner[len('because('):-1]
                parts = self.split_prolog_terms(because_inner)
                if len(parts) < 4:
                    continue

                rule_num = parts[0].strip()
                rule_desc_part = parts[1].strip()
                derived_fact = parts[2].strip()
                precond_part = parts[3].strip()

                rd_match = re.match(r"rule_desc\('([^']*)',([^\)]+)\)", rule_desc_part)
                if not rd_match:
                    continue

                desc_text = sanitize_desc(rd_match.group(1))
                confidence = rd_match.group(2).strip()

                if precond_part.startswith('[') and precond_part.endswith(']'):
                    precond_inner = precond_part[1:-1]
                else:
                    precond_inner = precond_part

                preconds = self.split_prolog_terms(precond_inner)
                preconds = [
                    predicate for predicate in preconds
                    if predicate
                    and not predicate.startswith("';'(")
                    and not predicate.startswith('=(')
                    # \+ (negation-as-failure) is not a graph edge and causes
                    # attack_graph parse errors — drop negative conditions.
                    and not predicate.startswith('\\+')
                ]

                rebuilt = (
                    "possible_duplicate_trace_step(because("
                    f"{rule_num},"
                    f"rule_desc('{desc_text}',{confidence}),"
                    f"{derived_fact},"
                    f"[{','.join(preconds)}]"
                    "))."
                )
                cleaned_terms.append(rebuilt.replace("''", "empty"))

            if not cleaned_terms:
                return None

            out_file = output_dir / 'trace_output_attackgraph.P'
            out_file.write_text("\n".join(cleaned_terms) + "\n", encoding='utf-8')
            print(f"    ✓ Prepared attack_graph-compatible trace: {out_file}")
            return out_file
        except Exception as error:
            print(f"    ✗ Failed to prepare attack_graph trace: {error}", file=sys.stderr)
            return None

    def parse_trace_to_json(self, trace_file: Path, paths_file: Path, host: str) -> None:
        if not trace_file.exists():
            return

        print("\n[+] Parsing attack graph trace...")

        try:
            content = trace_file.read_text(encoding='utf-8', errors='replace')

            attack_goals: List[str] = []
            # Goals are derived from the real terminal facts (execCode/compromise/flag_obtained)
            # after fact_to_step is built — see below. The hardcoded meta(attackGoal,N) mapping
            # was dropped because it injected spurious empty paths.

            # Also look for direct attack() statements (legacy support)
            for match in re.finditer(r'^attack\(', content, re.MULTILINE):
                start = match.end()
                depth = 1
                index = start
                while index < len(content) and depth > 0:
                    if content[index] == '(':
                        depth += 1
                    elif content[index] == ')':
                        depth -= 1
                    index += 1
                goal = content[start:index - 1]
                attack_goals.append(goal)

            # Collect ALL justifications per derived fact. A fact is an OR-node: MulVAL can derive it
            # by several rules/routes (e.g. compromise(Host,user) via an XSS credential route AND via
            # a tier-2 heuristic path-traversal route). Keeping every justification lets each route
            # surface as its own path instead of one silently displacing the other.
            fact_to_steps: Dict[str, List[Dict[str, object]]] = {}
            for match in re.finditer(r'because\(', content):
                start = match.end()
                depth = 1
                index = start
                while index < len(content) and depth > 0:
                    if content[index] == '(':
                        depth += 1
                    elif content[index] == ')':
                        depth -= 1
                    index += 1
                inner = content[start:index - 1]

                parts = self.split_prolog_terms(inner)
                if len(parts) < 4:
                    continue

                rule_id = parts[0].strip()
                rule_desc_part = parts[1].strip()
                derived_fact = parts[2].strip()
                precond_part = parts[3].strip()

                rd_match = re.match(r"rule_desc\('([^']+)',([\d.eE+-]+)\)", rule_desc_part)
                if not rd_match:
                    continue

                if precond_part.startswith('[') and precond_part.endswith(']'):
                    precond_inner = precond_part[1:-1]
                else:
                    precond_inner = precond_part

                precond_list = self.split_prolog_terms(precond_inner)
                precond_list = [
                    predicate for predicate in precond_list
                    if predicate and not predicate.startswith("';'") and not predicate.startswith('=(')
                ]

                fact_to_steps.setdefault(derived_fact, []).append({
                    'rule_id': int(rule_id) if rule_id.isdigit() else 0,
                    'description': rd_match.group(1),
                    'confidence': float(rd_match.group(2)),
                    'preconditions': precond_list,
                })

            # Best (highest-confidence) single justification per fact, used to expand preconditions
            # into a tree. Preferring higher confidence makes a proven-dataflow route (conf ~0.9) win
            # over a tier-2 heuristic route (conf ~0.5) at any shared intermediate fact — the old code
            # kept whichever justification appeared last in the trace, which let heuristic routes
            # displace the real required-vuln route from the emitted path.
            fact_to_step: Dict[str, Dict[str, object]] = {
                fact: max(steps, key=lambda s: s['confidence'])
                for fact, steps in fact_to_steps.items()
            }

            # Goals = the real derived terminal facts only. graph_gen.sh emits an
            # attack(Goal) fact for every QUERIED goal regardless of whether it was actually
            # derived, so the legacy attack(...) scan above is not proof of reachability —
            # gate it on fact_to_step too, otherwise unreached goals produce phantom
            # zero-technique, zero-confidence "paths" that look like real attack paths but
            # carry no information. flag-localized compromises are surfaced first (most
            # actionable), then other compromises, then execCode.
            # recon_complete is a terminal too (so the reconnaissance overview is always
            # captured as a path), but it is orientation only — never a confirmed exploit — so
            # it ranks strictly below every compromise/execCode goal.
            def _is_terminal(fact: str) -> bool:
                return fact.startswith(
                    ('compromise(', 'execCode(', 'flag_obtained(', 'recon_complete(')
                )

            def _is_recon(fact: str) -> bool:
                return fact.startswith('recon_complete(')
            derived_goals = [f for f in fact_to_step if _is_terminal(f)]
            derived_goals.sort(key=lambda f: (
                3 if _is_recon(f) else (
                    0 if 'flag_' in f else (1 if f.startswith('compromise(') else 2)), f))
            legacy_goals = [g for g in attack_goals if g in fact_to_step and g not in derived_goals]
            attack_goals = derived_goals + legacy_goals

            attack_paths: List[Dict[str, object]] = []
            path_id = 0
            seen_paths: Set[Tuple[str, frozenset]] = set()
            for goal in attack_goals:
                # Emit one path per distinct top-level justification of the terminal goal so that
                # every route reaching it surfaces (deeper facts still expand via the
                # highest-confidence justification in fact_to_step, keeping each path a tree).
                root_justifications = [j for j in fact_to_steps.get(goal, []) if j]
                if not root_justifications and goal in fact_to_step:
                    root_justifications = [fact_to_step[goal]]

                for root in root_justifications:
                    steps: List[Dict[str, object]] = [{
                        'type': 'technique',
                        'rule_description': root['description'],
                        'confidence': root['confidence'],
                        'derived_fact': goal,
                    }]
                    visited = {goal}
                    queue = list(root['preconditions'])

                    while queue:
                        fact = queue.pop(0)
                        if fact in visited:
                            continue
                        visited.add(fact)

                        if fact in fact_to_step:
                            step_info = fact_to_step[fact]
                            steps.append({
                                'type': 'technique',
                                'rule_description': step_info['description'],
                                'confidence': step_info['confidence'],
                                'derived_fact': fact,
                            })
                            for precond in step_info['preconditions']:
                                if precond not in visited:
                                    queue.append(precond)
                        else:
                            steps.append({
                                'type': 'precondition',
                                'description': fact,
                            })

                    preconditions = [step for step in steps if step['type'] == 'precondition']
                    techniques = sorted(
                        [step for step in steps if step['type'] == 'technique'],
                        key=lambda step: step.get('confidence', 0),
                        reverse=True,
                    )

                    # Two routes that expand to the same set of technique facts are the same path.
                    signature = (goal, frozenset(step['derived_fact'] for step in techniques))
                    if signature in seen_paths:
                        continue
                    seen_paths.add(signature)

                    path_id += 1
                    attack_paths.append({
                        'path_id': path_id,
                        'goal': goal,
                        'length': len(steps),
                        'technique_count': len(techniques),
                        'min_confidence': min(
                            (step['confidence'] for step in techniques),
                            default=0,
                        ),
                        'steps': preconditions + techniques,
                    })

            # Surface the most actionable paths first: confirmed exploit paths (highest
            # confidence, then fewest steps) ahead of the recon overview, which is always last.
            attack_paths.sort(
                key=lambda path: (
                    1 if str(path['goal']).startswith('recon_complete(') else 0,
                    -path.get('min_confidence', 0),
                    path['technique_count'],
                ),
            )

            output = {
                'total_paths': len(attack_paths),
                'attack_goals': attack_goals,
                'target_host': host,
                'paths': attack_paths,
            }

            paths_file.write_text(json.dumps(output, indent=2), encoding='utf-8')

            print(f"    ✓ Generated {len(attack_paths)} attack paths in {paths_file}")
            if attack_paths:
                max_depth = max(path['technique_count'] for path in attack_paths)
                avg_depth = sum(path['technique_count'] for path in attack_paths) / len(attack_paths)
                print(f"    Path depths: max={max_depth}, avg={avg_depth:.1f}")
        except Exception as error:
            print(f"    ✗ Failed to parse trace: {error}", file=sys.stderr)
            traceback.print_exc()
