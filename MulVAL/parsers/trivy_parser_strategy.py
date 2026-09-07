#!/usr/bin/env python3
"""Trivy parser strategy."""

import json
import sys
from typing import Any, Dict, List, Set

from base_parser import Predicate, ScannerStrategy

MAX_CVES = 20


class TrivyParserStrategy(ScannerStrategy):
    """Parse Trivy JSON output and emit high-value vulnerability predicates."""

    def __init__(self, host: str = 'localhost'):
        super().__init__(host=host)
        self.cves: List[Dict[str, Any]] = []

    def get_scanner_name(self) -> str:
        return "Trivy"

    def parse(self, input_file: str) -> List[Predicate]:
        self.clear()
        self.cves = []

        try:
            with open(input_file, 'r', encoding='utf-8') as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError) as error:
            print(f"[!] Warning: Failed to parse Trivy file {input_file}: {error}", file=sys.stderr)
            return []

        seen_cves: Set[str] = set()
        cve_list: List[Dict[str, Any]] = []

        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                cve_id = vuln.get('VulnerabilityID', '')
                severity = vuln.get('Severity', 'UNKNOWN').upper()
                pkg_name = vuln.get('PkgName', 'unknown')

                if severity not in ('CRITICAL', 'HIGH'):
                    continue
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)

                cve_list.append({
                    'cve_id': cve_id,
                    'package': pkg_name,
                    'version': vuln.get('InstalledVersion', 'unknown'),
                    'severity': severity,
                    'description': vuln.get('Description', '')[:120],
                })

        cve_list.sort(key=lambda item: (0 if item['severity'] == 'CRITICAL' else 1, item['cve_id']))
        cve_list = cve_list[:MAX_CVES]

        host_s = self.sanitize(self.host)
        for cve in cve_list:
            cve_id = cve['cve_id']
            # Use sanitize (quoted) not atom — package names can contain @, /, - etc.
            pkg = self.sanitize(cve['package'])

            self.add_predicate(
                f"vuln({host_s}, {self.sanitize(cve_id)}, {pkg}).",
                'critical_cves',
                cve,
            )

            if cve['severity'] == 'CRITICAL':
                self.add_predicate(
                    f"exploit_possible({self.sanitize(cve_id)}).",
                    'exploits',
                    {'cve': cve_id},
                )

            self.cves.append(cve)

        crits = sum(1 for c in cve_list if c['severity'] == 'CRITICAL')
        highs = len(cve_list) - crits
        print(f"[Trivy] Kept {crits} Critical + {highs} High CVEs (from {len(seen_cves)} total unique)")
        return self.predicates
