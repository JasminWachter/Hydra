#!/usr/bin/env python3
"""Scanner execution component."""

import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional


class ScannerExecutor:
    """Executes external scanners and tracks output files."""

    def __init__(
        self,
        target: Path,
        output_dir: Path,
        host: str,
        nmap_profile: str = 'full',
        nmap_ports: Optional[str] = None,
    ):
        self.target = target
        self.output_dir = output_dir
        self.host = host
        self.nmap_profile = nmap_profile if nmap_profile in {'full', 'fast'} else 'full'
        # Web-relevant ports only; DB/ssh ports are rarely exposed in web CTF targets and add
        # nothing the web KB consumes. Callers (the benchmark harness) normally pass the single
        # resolved container port explicitly, so this is a manual-run fallback only.
        self.nmap_ports = nmap_ports or '80,443,3000,8000,8080,8443'

    def run_scanner(self, scanner_name: str, scanner_outputs: Dict[str, str], force: bool = False) -> bool:
        """Execute a specific scanner and register its output path."""
        output_file = self.output_dir / 'scan_results' / f"{scanner_name}_results.json"

        if not force and output_file.exists() and output_file.stat().st_size > 100:
            print(f"[+] Using existing {scanner_name} results: {output_file}")
            scanner_outputs[scanner_name] = str(output_file)
            return True

        print(f"[+] Running {scanner_name} scan...")

        if scanner_name == 'trivy':
            return self._run_trivy(output_file, scanner_outputs)
        if scanner_name == 'nmap':
            return self._run_nmap(output_file, scanner_outputs)
        if scanner_name == 'semgrep':
            return self._run_semgrep(output_file, scanner_outputs)

        print(f"[!] Unknown scanner: {scanner_name}", file=sys.stderr)
        return False

    def _run_trivy(self, output_file: Path, scanner_outputs: Dict[str, str]) -> bool:
        try:
            cmd = [
                'trivy', 'fs',
                # Only 'vuln' findings are parsed (secret/misconfig are scanned but never
                # consumed) - keep the scan scoped to what actually becomes a predicate.
                '--scanners', 'vuln',
                '--format', 'json',
                '--output', str(output_file),
                str(self.target),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                print(f"    ✓ Trivy scan completed: {output_file}")
                scanner_outputs['trivy'] = str(output_file)
                return True

            print(f"    ✗ Trivy scan failed: {result.stderr}", file=sys.stderr)
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            print(f"    ✗ Trivy error: {error}", file=sys.stderr)
            return False

    # The only NSE scripts the parser reads (_parse_nmap_script): http-methods, http-title,
    # http-server-header, http-default-accounts, mongodb-info. -sC's full default script set
    # is unused overhead, and OS detection (-O) needs raw-socket/root privileges we don't
    # reliably have and its output (osmatch -> os/2) is never emitted by this command anyway.
    _NSE_SCRIPTS = 'http-methods,http-title,http-server-header,http-default-accounts,mongodb-info'

    def _run_nmap(self, output_file: Path, scanner_outputs: Dict[str, str]) -> bool:
        xml_output_file = output_file.with_suffix('.xml')

        try:
            if self.nmap_profile == 'fast':
                # Fast profile: keep service detection but skip scripts, reduce retries, and
                # cap host scan time for benchmark throughput.
                base_args = [
                    '-Pn', '-sV', '--version-light',
                    '--max-retries', '1', '--host-timeout', '20s', '-T4',
                    '-p', self.nmap_ports,
                    '-oX', str(xml_output_file),
                    self.host,
                ]
                timeout_sec = 90
            else:
                base_args = [
                    '-Pn', '-sV', '--script', self._NSE_SCRIPTS,
                    '-p', self.nmap_ports,
                    '-oX', str(xml_output_file),
                    self.host,
                ]
                timeout_sec = 300

            # -sV/-sT + --script don't require raw sockets, so this runs unprivileged.
            result = subprocess.run(['nmap'] + base_args, capture_output=True, text=True, timeout=timeout_sec)

            if result.returncode == 0 or xml_output_file.exists():
                print(f"    ✓ Nmap scan completed: {xml_output_file}")
                scanner_outputs['nmap'] = str(xml_output_file)
                return True

            print(f"    ✗ Nmap scan failed: {result.stderr}", file=sys.stderr)
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            print(f"    ✗ Nmap error: {error}", file=sys.stderr)
            return False

    def _run_semgrep(self, output_file: Path, scanner_outputs: Dict[str, str]) -> bool:
        # Custom taint rules localize source->sink dataflow and flag locations across every
        # language the ruleset covers (PHP/JS/Python/Java). The stock owasp pack is a fallback
        # for classes the custom rules don't cover.
        rules_dir = Path(__file__).resolve().parent / 'semgrep_rules'
        try:
            target_abs = self.target.resolve()
            cmd = [
                'semgrep', 'scan',
                '--config', str(rules_dir),
                '--config', 'p/owasp-top-ten',
                '--json', '--quiet', str(target_abs),
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.returncode == 0 and result.stdout.strip():
                output_file.write_text(result.stdout, encoding='utf-8')
                print(f"    ✓ Semgrep scan completed: {output_file}")
                scanner_outputs['semgrep'] = str(output_file)
                return True

            print(f"    ✗ Semgrep scan failed: {result.stderr[:300]}", file=sys.stderr)
            return False
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            print(f"    ✗ Semgrep error: {error}", file=sys.stderr)
            return False
