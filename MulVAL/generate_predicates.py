#!/usr/bin/env python3
"""
Unified MulVAL Predicate Generation Pipeline
Consolidates scanning, parsing, and MulVAL execution using Strategy pattern.
"""
import argparse
import sys
from pathlib import Path
from typing import Dict, Optional

sys.path.insert(0, str(Path(__file__).parent / 'parsers'))

from base_parser import PredicateAggregator
from scanner_strategy_factory import ScannerStrategyFactory
from scanner_executor import ScannerExecutor
from trace_processor import TraceProcessor
from mulval_executor import MulvalExecutor
from report_generator import ReportGenerator


class UnifiedPipeline:
    """Orchestrates scanner execution, predicate generation, and MulVAL integration."""

    def __init__(
        self,
        target: str,
        output_dir: str,
        host: str = 'localhost',
        nmap_profile: str = 'full',
        nmap_ports: Optional[str] = None,
    ):
        self.target = Path(target)
        self.output_dir = Path(output_dir)
        self.host = host

        self.scanner_outputs: Dict[str, str] = {}
        # A single, unambiguous port (live mode) is an authoritative signal of the real
        # target; a comma-separated range (static mode default) is just a guess and
        # shouldn't be force-fed to app-feature port inference.
        live_port = None
        if nmap_ports and ',' not in nmap_ports:
            try:
                live_port = int(nmap_ports)
            except ValueError:
                live_port = None
        self.aggregator = PredicateAggregator(host=host, live_port=live_port)

        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / 'scan_results').mkdir(exist_ok=True)

        for scanner_type in ScannerStrategyFactory.get_available_scanners():
            strategy = ScannerStrategyFactory.create_strategy(scanner_type, host=host)
            # The Semgrep strategy needs the source root for port inference + param extraction.
            if hasattr(strategy, 'target_dir'):
                strategy.target_dir = self.target
            self.aggregator.register_strategy(scanner_type, strategy)

        base_dir = Path(__file__).parent.resolve()
        self.scanner_executor = ScannerExecutor(
            target=self.target,
            output_dir=self.output_dir,
            host=self.host,
            nmap_profile=nmap_profile,
            nmap_ports=nmap_ports,
        )
        self.trace_processor = TraceProcessor()
        self.mulval_executor = MulvalExecutor(
            base_dir=base_dir,
            output_dir=self.output_dir,
            host=self.host,
            trace_processor=self.trace_processor,
        )
        self.report_generator = ReportGenerator(
            target=self.target,
            output_dir=self.output_dir,
            host=self.host,
        )

    def run_scanner(self, scanner_name: str, force: bool = False) -> bool:
        """Execute one scanner and track output path."""
        return self.scanner_executor.run_scanner(
            scanner_name=scanner_name,
            scanner_outputs=self.scanner_outputs,
            force=force,
        )

    def parse_scanner_outputs(self) -> Path:
        """Parse scanner outputs and write MulVAL input predicates."""
        print("\n[+] Parsing scanner results...")
        self.aggregator.parse_all(self.scanner_outputs)
        # Augment scanner findings with app-level static features.
        self.aggregator.add_app_features(str(self.target))
        self.aggregator.add_network_context(attacker_location='internet')

        predicates_file = self.output_dir / 'input_predicates.P'
        self.aggregator.write_predicates(str(predicates_file))
        return predicates_file

    def run_mulval(self, predicates_file: Path, rules_file: Optional[Path] = None) -> bool:
        """Execute MulVAL and parse outputs."""
        return self.mulval_executor.run(predicates_file=predicates_file, rules_file=rules_file)

    def generate_report(self, predicates_file: Path) -> None:
        """Generate a scan summary report."""
        self.report_generator.generate(
            predicates_file=predicates_file,
            scanner_outputs=self.scanner_outputs,
            total_predicates=len(self.aggregator.predicates),
            scanner_stats=self.aggregator.get_all_statistics(),
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Unified MulVAL Predicate Generation Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all scanners and generate predicates
  %(prog)s --target /path/to/code --output ./graphs

  # Run specific scanners only
    %(prog)s --target /path/to/code --scanners trivy,semgrep

  # Use existing scan results
  %(prog)s --skip-scanning --trivy-json scan_results/trivy_results.json

  # Custom rules and skip MulVAL execution
  %(prog)s --target /path/to/code --rules custom_rules.P --skip-mulval
        """,
    )

    parser.add_argument('--target', required=True, help='Target directory or application to scan')
    parser.add_argument('--output', default='./graphs', help='Output directory for results (default: ./graphs)')
    parser.add_argument('--host', default='localhost', help='Host identifier for predicates (default: localhost)')
    parser.add_argument(
        '--scanners',
        default='trivy,semgrep',
        help='Comma-separated list of scanners to run (default: trivy,semgrep)',
    )
    parser.add_argument('--skip-scanning', action='store_true', help='Skip scanning, use existing results')
    parser.add_argument('--force-rescan', action='store_true', help='Force rescan even if results exist')
    parser.add_argument('--trivy-json', help='Path to existing Trivy JSON output')
    parser.add_argument('--nmap-xml', help='Path to existing Nmap XML output')
    parser.add_argument('--semgrep-json', help='Path to existing Semgrep JSON output')
    parser.add_argument('--skip-mulval', action='store_true', help='Skip MulVAL graph generation')
    parser.add_argument('--rules', help='Path to custom interaction rules file')
    parser.add_argument('--no-report', action='store_true', help='Skip report generation')
    parser.add_argument(
        '--nmap-profile',
        choices=['full', 'fast'],
        default='full',
        help='Nmap execution profile (default: full)',
    )
    parser.add_argument(
        '--nmap-ports',
        help='Optional explicit Nmap port list, e.g. 80,443,8080',
    )

    return parser


def _configure_scanner_inputs(args: argparse.Namespace, pipeline: UnifiedPipeline) -> None:
    if not args.skip_scanning:
        scanners = [scanner.strip() for scanner in args.scanners.split(',')]
        for scanner in scanners:
            if scanner in ScannerStrategyFactory.get_available_scanners():
                pipeline.run_scanner(scanner, force=args.force_rescan)
            else:
                print(f"[!] Unknown scanner: {scanner}", file=sys.stderr)
        return

    if args.trivy_json:
        pipeline.scanner_outputs['trivy'] = args.trivy_json
    if args.nmap_xml:
        pipeline.scanner_outputs['nmap'] = args.nmap_xml
    if args.semgrep_json:
        pipeline.scanner_outputs['semgrep'] = args.semgrep_json


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    print("=" * 70)
    print("  MulVAL Unified Pipeline - Strategy-based Predicate Generation")
    print("=" * 70)
    print(f"\nTarget:  {args.target}")
    print(f"Output:  {args.output}")
    print(f"Host:    {args.host}\n")

    pipeline = UnifiedPipeline(
        target=args.target,
        output_dir=args.output,
        host=args.host,
        nmap_profile=args.nmap_profile,
        nmap_ports=args.nmap_ports,
    )
    _configure_scanner_inputs(args=args, pipeline=pipeline)

    if not pipeline.scanner_outputs:
        print("\n[!] Error: No scanner outputs available", file=sys.stderr)
        print("    Run scanners or provide existing JSON files", file=sys.stderr)
        sys.exit(1)

    predicates_file = pipeline.parse_scanner_outputs()

    if not args.skip_mulval:
        rules_file = Path(args.rules) if args.rules else None
        if not pipeline.run_mulval(predicates_file=predicates_file, rules_file=rules_file):
            print("\n[!] MulVAL attack graph generation failed", file=sys.stderr)
            sys.exit(1)

    if not args.no_report:
        pipeline.generate_report(predicates_file=predicates_file)

    print("\n" + "=" * 70)
    print("  ✓ Pipeline completed successfully!")
    print("=" * 70)


if __name__ == '__main__':
    main()
