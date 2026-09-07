#!/usr/bin/env python3
"""Summary report generation component."""

from pathlib import Path
from typing import Dict


class ReportGenerator:
    """Writes and prints a scan summary report."""

    def __init__(self, target: Path, output_dir: Path, host: str):
        self.target = target
        self.output_dir = output_dir
        self.host = host

    def generate(
        self,
        predicates_file: Path,
        scanner_outputs: Dict[str, str],
        total_predicates: int,
        scanner_stats: Dict[str, Dict[str, int]],
    ) -> Path:
        print("\n[+] Generating summary report...")

        report_file = self.output_dir / 'scan_summary.txt'

        with open(report_file, 'w', encoding='utf-8') as report:
            report.write("=" * 70 + "\n")
            report.write("  MulVAL Unified Pipeline - Scan Summary\n")
            report.write("=" * 70 + "\n\n")

            report.write(f"Target:  {self.target}\n")
            report.write(f"Host:    {self.host}\n")
            report.write(f"Output:  {self.output_dir}\n\n")

            report.write("Scanners Executed:\n")
            for scanner, output in scanner_outputs.items():
                report.write(f"  ✓ {scanner.ljust(15)} → {output}\n")

            report.write(f"\nGenerated Predicates: {predicates_file}\n")

            if scanner_stats:
                report.write("\nPredicate Statistics:\n")
                for scanner, stats in scanner_stats.items():
                    total = stats.get('total_predicates', 0)
                    if total > 0:
                        report.write(f"  {scanner.ljust(15)} → {total} predicates\n")

            report.write(f"\nTotal Predicates: {total_predicates}\n")

        print(f"    ✓ Report saved: {report_file}")
        print("\n" + "=" * 70)
        print(report_file.read_text(encoding='utf-8', errors='replace'))
        return report_file
