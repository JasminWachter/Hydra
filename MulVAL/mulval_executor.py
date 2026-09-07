#!/usr/bin/env python3
"""MulVAL execution component."""

import shutil
import subprocess
import sys
from os.path import commonpath
from pathlib import Path
from typing import Optional

from trace_processor import TraceProcessor


_TRACE_FILENAME = "trace_output.P"


class MulvalExecutor:
    """Runs MulVAL and attack_graph generation using Docker or local tools."""

    def __init__(self, base_dir: Path, output_dir: Path, host: str, trace_processor: TraceProcessor):
        self.base_dir = base_dir
        self.output_dir = output_dir
        self.host = host
        self.trace_processor = trace_processor

    def resolve_rules_file(self, rules_file: Optional[Path]) -> Optional[Path]:
        if rules_file is not None:
            print(f"    Using custom rules: {rules_file}")
            return rules_file

        web_rules = self.base_dir / 'kb' / 'web_security_rules.P'

        # web_security_rules.P is the sole KB: it already spans the full kill chain
        # (recon_complete -> vuln surface -> confirmed -> initial_access -> exec_achieved ->
        # compromise -> execCode, with MITRE technique ids in the rule descriptions) and its
        # recon tier guarantees a graph is produced for every reachable target.
        #
        # full_post_exploit_rules.P is intentionally NOT combined in: appending it breaks
        # MulVAL derivation — no-evidence targets stop deriving recon_complete and execCode
        # becomes spuriously "derivable" with an empty trace, so most tasks yield an empty
        # graph. Bisection confirmed the web rules alone trace correctly (recon for
        # no-evidence targets, full exploit chains for taint-localized ones) while the
        # combined ruleset does not. Re-integrating a fixed post-exploitation layer is a
        # separate task.
        if web_rules.exists():
            print(f"    Using web security assessment rules: {web_rules}")
            return web_rules

        print("    ✗ No rules file found", file=sys.stderr)
        return None

    def run(self, predicates_file: Path, rules_file: Optional[Path] = None) -> bool:
        print("\n[+] Running MulVAL attack graph generation...")

        resolved_rules = self.resolve_rules_file(rules_file)
        if resolved_rules is None:
            return False

        if not resolved_rules.exists():
            print(f"    ✗ Rules file not found: {resolved_rules}", file=sys.stderr)
            return False

        out_dir = self.output_dir.resolve()
        pred_abs = predicates_file.resolve()
        rules_abs = resolved_rules.resolve()

        local_ok = self._run_mulval_local(pred_abs, rules_abs)
        if local_ok:
            return True

        docker_ok = self._run_mulval_docker(out_dir, pred_abs, rules_abs)
        if not docker_ok:
            return False
        return self._finalize_mulval_outputs()

    def _run_mulval_docker(self, out_dir: Path, pred_abs: Path, rules_abs: Path) -> bool:
        if not shutil.which('docker'):
            return False

        try:
            check = subprocess.run(['docker', 'info'], capture_output=True, text=True, timeout=10)
            if check.returncode != 0:
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

        print("    Running via Docker (wilbercui/mulval:latest)...")

        mount_root = Path(commonpath([str(self.base_dir), str(out_dir), str(pred_abs), str(rules_abs)])).resolve()
        out_rel = out_dir.relative_to(mount_root)
        pred_rel = pred_abs.relative_to(mount_root)
        rules_rel = rules_abs.relative_to(mount_root)

        cmd = [
            'docker', 'run', '--rm',
            '-v', f'{mount_root}:/data',
            '-w', f'/data/{out_rel}',
            'wilbercui/mulval',
            'bash', '-lc',
            f'graph_gen.sh /data/{pred_rel} -r /data/{rules_rel} -v -e',
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                if result.stderr:
                    print(f"    Docker stderr: {result.stderr[:300]}", file=sys.stderr)
                return False
            return True
        except subprocess.TimeoutExpired:
            print("    ✗ Docker MulVAL timed out (120s)", file=sys.stderr)
            return False
        except Exception as error:
            print(f"    ✗ Docker execution error: {error}", file=sys.stderr)
            return False

    def _run_mulval_local(self, pred_abs: Path, rules_abs: Path) -> bool:
        try:
            cmd = ['graph_gen.sh', str(pred_abs), '-r', str(rules_abs), '-v', '-e']
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(self.output_dir), timeout=120)

            trace_file = self.output_dir / _TRACE_FILENAME
            if trace_file.exists() and trace_file.stat().st_size > 100:
                normalized = self.trace_processor.normalize_trace_output(trace_file)
                if normalized:
                    print("    ✓ Normalized trace_output.P for MulVAL parser compatibility")

                attack_graph_trace = self.trace_processor.prepare_attack_graph_trace(trace_file, self.output_dir)
                graph_ok = False
                if attack_graph_trace is not None:
                    graph_ok = self._generate_attack_graph_local(attack_graph_trace)
                if not graph_ok:
                    print("    ! MulVAL visual graph generation failed (trace still available)", file=sys.stderr)
                    return False
                print(f"    ✓ MulVAL visual graph generated: {self.output_dir / 'AttackGraph.pdf'}")

                print("    ✓ MulVAL execution completed")
                print(f"    Output: {trace_file}")
                self.trace_processor.parse_trace_to_json(
                    trace_file=trace_file,
                    paths_file=self.output_dir / 'paths.json',
                    host=self.host,
                )
                return True

            if result.returncode == 0:
                print("    ✗ MulVAL produced no trace output", file=sys.stderr)
                return False

            print(f"    ✗ MulVAL execution failed: {result.stderr}", file=sys.stderr)
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            print(f"    ✗ MulVAL error: {error}", file=sys.stderr)
            print("    Note: Install XSB Prolog + MulVAL, or use Docker", file=sys.stderr)
            print(
                "    Docker: docker run --rm -v <dir>:/data wilbercui/mulval "
                "bash -lc \"graph_gen.sh <input> -r <rules> -v\"",
                file=sys.stderr,
            )
            return False

    def _finalize_mulval_outputs(self) -> bool:
        trace_file = self.output_dir / _TRACE_FILENAME
        if not (trace_file.exists() and trace_file.stat().st_size > 100):
            print("    ✗ MulVAL produced no trace output", file=sys.stderr)
            return False

        attack_graph_trace = self.trace_processor.prepare_attack_graph_trace(trace_file, self.output_dir)
        graph_ok = False
        if attack_graph_trace is not None:
            graph_ok = self._generate_attack_graph_docker(attack_graph_trace.name)

        if not graph_ok:
            print("    ! MulVAL visual graph generation failed (trace still available)", file=sys.stderr)
            return False
        print(f"    ✓ MulVAL visual graph generated: {self.output_dir / 'AttackGraph.pdf'}")

        print("    ✓ MulVAL execution completed")
        print(f"    Output: {trace_file}")

        self.trace_processor.parse_trace_to_json(
            trace_file=trace_file,
            paths_file=self.output_dir / 'paths.json',
            host=self.host,
        )
        return True

    def _generate_attack_graph_docker(self, trace_filename: str) -> bool:
        if not shutil.which('docker'):
            return False

        out_dir = self.output_dir.resolve()
        base_dir = self.base_dir.resolve()
        mount_root = Path(commonpath([str(base_dir), str(out_dir)])).resolve()
        out_rel = out_dir.relative_to(mount_root)
        cmd = [
            'docker', 'run', '--rm',
            '-v', f'{mount_root}:/data',
            '-w', f'/data/{out_rel}',
            'wilbercui/mulval',
            'bash', '-lc',
            (
                # attack_graph always reads the hardcoded filename trace_output.P
                # from the working directory — copy the prepared trace there first.
                f"cp {trace_filename} trace_output.P "
                "&& attack_graph -l trace_output.P > AttackGraph.txt "
                "&& grep -E 'AND|OR|LEAF' AttackGraph.txt > VERTICES.CSV "
                "&& grep -Ev 'AND|OR|LEAF' AttackGraph.txt > ARCS.CSV "
                "&& render.sh"
            ),
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            pdf_file = self.output_dir / 'AttackGraph.pdf'
            return result.returncode == 0 and pdf_file.exists() and pdf_file.stat().st_size > 0
        except Exception as error:
            print(f"    ✗ attack_graph Docker error: {error}", file=sys.stderr)
            return False

    def _generate_attack_graph_local(self, attack_graph_trace: Path) -> bool:
        try:
            # attack_graph always reads trace_output.P from cwd — copy the prepared trace.
            dest = self.output_dir / _TRACE_FILENAME
            shutil.copy(attack_graph_trace, dest)
            result = subprocess.run(
                ['attack_graph', '-l', _TRACE_FILENAME],
                capture_output=True, text=True,
                cwd=str(self.output_dir), timeout=120,
            )

            if result.returncode != 0 or not result.stdout.strip():
                if result.stderr:
                    print(f"    ✗ attack_graph failed: {result.stderr[:300]}", file=sys.stderr)
                return False

            attack_graph_file = self.output_dir / 'AttackGraph.txt'
            lines = result.stdout.splitlines()
            attack_graph_file.write_text(result.stdout, encoding='utf-8')
            vertices = [line for line in lines if any(kind in line for kind in ('AND', 'OR', 'LEAF'))]
            arcs = [line for line in lines if line not in vertices]
            (self.output_dir / 'VERTICES.CSV').write_text('\n'.join(vertices) + '\n', encoding='utf-8')
            (self.output_dir / 'ARCS.CSV').write_text('\n'.join(arcs) + '\n', encoding='utf-8')

            render = subprocess.run(
                ['render.sh'],
                capture_output=True, text=True,
                cwd=str(self.output_dir), timeout=120,
            )
            pdf_file = self.output_dir / 'AttackGraph.pdf'
            return render.returncode == 0 and pdf_file.exists() and pdf_file.stat().st_size > 0
        except Exception as error:
            print(f"    ✗ attack_graph local error: {error}", file=sys.stderr)
            return False
