#!/usr/bin/env python3
"""
Base parser classes implementing Strategy design pattern for scanner parsers.
Produces MulVAL-compatible predicates that activate MITRE ATT&CK interaction rules.
"""
from abc import ABC, abstractmethod
from typing import List, Set, Dict, Any, Optional
from pathlib import Path

from app_feature_extractor import AppFeatureExtractor


class Predicate:
    """Represents a single Prolog predicate with optional metadata."""

    def __init__(self, predicate: str, category: str = 'unknown',
                 metadata: Optional[Dict[str, Any]] = None):
        self.predicate = predicate
        self.category = category
        self.metadata = metadata or {}

    def __str__(self) -> str:
        return self.predicate

    def __hash__(self) -> int:
        return hash(self.predicate)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Predicate):
            return self.predicate == other.predicate
        return False


class ScannerStrategy(ABC):
    """Abstract base class for scanner parsing strategies."""

    def __init__(self, host: str = 'localhost'):
        self.host = host
        self.predicates: List[Predicate] = []
        self.seen_predicates: Set[str] = set()
        self._stats: Dict[str, int] = {}

    @staticmethod
    def sanitize(s: str) -> str:
        """Sanitize string for Prolog atom - wrap in single quotes."""
        return "'" + str(s).replace("'", "").replace("\\", "/") + "'"

    @staticmethod
    def atom(s: str) -> str:
        """Create a Prolog atom (lowercase, no special chars)."""
        return str(s).replace('-', '_').replace('.', '_').replace(' ', '_').lower()

    def add_predicate(self, predicate: str, category: str = 'unknown',
                      metadata: Optional[Dict[str, Any]] = None):
        """Add predicate if not already added (deduplication)."""
        if predicate not in self.seen_predicates:
            pred_obj = Predicate(predicate, category, metadata)
            self.predicates.append(pred_obj)
            self.seen_predicates.add(predicate)
            self._stats[category] = self._stats.get(category, 0) + 1

    @abstractmethod
    def parse(self, input_file: str) -> List[Predicate]:
        """Parse scanner output file and return list of predicates."""
        pass

    @abstractmethod
    def get_scanner_name(self) -> str:
        """Return the name of the scanner this strategy handles."""
        pass

    def get_statistics(self) -> Dict[str, int]:
        """Return parsing statistics."""
        return {
            'total_predicates': len(self.predicates),
            'scanner': self.get_scanner_name(),
            **self._stats
        }

    def clear(self):
        """Clear all predicates and statistics."""
        self.predicates.clear()
        self.seen_predicates.clear()
        self._stats.clear()


# -- Service classification maps --

WEB_SERVICES = {
    'http', 'https', 'http-proxy', 'http-alt', 'httpd', 'nginx',
    'apache', 'node', 'express', 'node_js_express_framework',
    'tomcat', 'jetty', 'flask', 'django', 'php', 'iis',
}

DATABASE_SERVICES = {
    'mysql', 'postgresql', 'postgres', 'mongodb', 'redis',
    'mssql', 'oracle', 'mariadb', 'couchdb', 'elasticsearch',
    'memcached', 'cassandra', 'sqlite',
}

AUTH_SERVICES = {
    'ssh', 'openssh', 'ftp', 'ftps', 'telnet', 'rdp',
    'vnc', 'smb', 'samba', 'ldap', 'kerberos',
}

# Ports commonly associated with web services
WEB_PORTS = {80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 4443}

# Map CVE package names to service names for correlation
PKG_TO_SERVICE = {
    'openssh': 'openssh',
    'openssl': 'openssl',
    'nginx': 'nginx',
    'apache': 'apache',
    'httpd': 'httpd',
    'node': 'node_js_express_framework',
    'nodejs': 'node_js_express_framework',
    'express': 'node_js_express_framework',
    'mongodb': 'mongodb',
    'mysql': 'mysql',
    'postgresql': 'postgresql',
    'redis': 'redis',
    'sqlite': 'sqlite',
    'libsqlite': 'sqlite',
    'curl': 'curl',
    'git': 'git',
    'python': 'python',
    'php': 'php',
}


class PredicateAggregator:
    """
    Aggregates predicates from multiple scanner strategies.
    Produces a focused, non-bloated predicate set for MulVAL.
    """

    def __init__(self, host: str = 'localhost', live_port: Optional[int] = None):
        self.host = host
        self.strategies: Dict[str, ScannerStrategy] = {}
        self.predicates: List[Predicate] = []
        self.seen_predicates: Set[str] = set()
        self._parsed_scanners: Set[str] = set()
        # Cross-scanner state for correlation
        self._services: List[Dict[str, Any]] = []  # from nmap
        self._cves: List[Dict[str, Any]] = []       # from vulnerability scanners (e.g., Trivy)
        # Seeded with the actual live-resolved port (not a scan-range guess) so app-feature
        # predicates land on the same port as taint_flow evidence even when nmap can't
        # positively fingerprint the service as 'http' (e.g. tcpwrapped responses).
        self._web_ports: Set[int] = {live_port} if live_port else set()
        self._app_feature_stats: Dict[str, int] = {}

    def register_strategy(self, name: str, strategy: ScannerStrategy):
        """Register a scanner strategy."""
        self.strategies[name] = strategy

    def parse_all(self, scanner_files: Dict[str, str]) -> List[Predicate]:
        """Parse all scanner outputs and perform cross-scanner correlation."""
        self._parsed_scanners.clear()
        # Parse nmap first (when present): it's the source of self._web_ports, and the
        # semgrep strategy needs that port *before* it parses so taint_flow lands on the
        # same port as nmap's connects/web_service (see _propagate_web_port_hint).
        ordered_names = sorted(scanner_files, key=lambda name: 0 if name == 'nmap' else 1)
        for scanner_name in ordered_names:
            file_path = scanner_files[scanner_name]
            if scanner_name in self.strategies and Path(file_path).exists():
                strategy = self.strategies[scanner_name]
                try:
                    self._parsed_scanners.add(scanner_name)
                    if scanner_name != 'nmap':
                        self._propagate_web_port_hint(strategy)
                        self._propagate_canonical_host(strategy)
                    predicates = strategy.parse(file_path)
                    for pred in predicates:
                        if pred.predicate not in self.seen_predicates:
                            self.predicates.append(pred)
                            self.seen_predicates.add(pred.predicate)
                    # Collect cross-scanner data
                    if hasattr(strategy, 'services'):
                        self._services.extend(strategy.services)
                    if hasattr(strategy, 'cves'):
                        self._cves.extend(strategy.cves)
                    if hasattr(strategy, 'web_ports'):
                        self._web_ports.update(strategy.web_ports)
                    if scanner_name == 'nmap':
                        self._adopt_canonical_host_from_nmap(strategy)
                except Exception as e:
                    print(f"[!] Warning: Failed to parse {scanner_name}: {e}")

        # Run cross-scanner correlation
        self._correlate_cves_to_services()
        return self.predicates

    def _propagate_web_port_hint(self, strategy: ScannerStrategy) -> None:
        """Give a strategy nmap's discovered web port, if it wants one and nmap found one."""
        if not self._web_ports or not hasattr(strategy, 'web_port_hint'):
            return
        strategy.web_port_hint = min(self._web_ports)

    def _adopt_canonical_host_from_nmap(self, strategy: ScannerStrategy) -> None:
        """Adopt nmap's discovered host atom (e.g. host_127_0_0_1) as the canonical host.

        nmap derives its host id from the scanned IP while every other producer (semgrep,
        app-features, network context, goals) defaults to 'localhost'. That aliasing means
        localized predicates like taint_flow/detected_vuln never share a (Host, Port) pair
        with nmap's connects/web_service, so the confirmation -> initial_access join silently
        fails. Canonicalizing to nmap's host once it is known keeps every fact joinable.
        """
        services = getattr(strategy, 'services', None)
        if services:
            host_id = services[0].get('host')
            if host_id:
                self.host = host_id

    def _propagate_canonical_host(self, strategy: ScannerStrategy) -> None:
        """Point a not-yet-parsed strategy at the canonical host so its predicates join."""
        strategy.host = self.host

    def _correlate_cves_to_services(self):
        """Correlate CVEs from vulnerability scanners with services from nmap."""
        if not self._services or not self._cves:
            return

        correlated = 0
        seen: Set[tuple] = set()
        for svc in self._services:
            svc_name = svc.get('service', '').lower()
            svc_product = svc.get('product', '').lower()
            port = svc.get('port', 0)
            host = svc.get('host', self.host)

            for cve in self._cves:
                pkg = cve.get('package', '').lower()
                cve_id = cve.get('cve_id', '')
                severity = cve.get('severity', '').upper()

                # Only correlate CRITICAL and HIGH CVEs with actual services
                if severity not in ('CRITICAL', 'HIGH'):
                    continue

                # Check if CVE package matches the service
                matched = False
                for pkg_prefix, svc_match in PKG_TO_SERVICE.items():
                    if pkg.startswith(pkg_prefix) and (
                        svc_match in svc_name or svc_match in svc_product
                    ):
                        matched = True
                        break

                if matched:
                    key = (host, port, cve_id, svc_name)
                    if key not in seen:
                        seen.add(key)
                        pred = (
                            f"remote_service_vulnerable({ScannerStrategy.sanitize(host)}, "
                            f"{port}, {ScannerStrategy.sanitize(cve_id)}, "
                            f"{ScannerStrategy.sanitize(svc_name)})."
                        )
                        self._add(pred, 'service_cve_correlation', {
                            'cve': cve_id, 'service': svc_name, 'port': port
                        })
                        correlated += 1

        if correlated:
            print(f"    [Correlation] Matched {correlated} CVEs to exposed services")

    def add_app_features(self, target_dir: str):
        """Extract web-app features from source files and emit activation predicates."""
        extractor = AppFeatureExtractor()
        result = extractor.extract(
            target_dir=Path(target_dir),
            host_atom=ScannerStrategy.atom(self.host),
            candidate_ports=self._web_ports,
        )

        self._app_feature_stats = dict(result.get('stats', {}))
        for predicate in result.get('predicates', []):
            self._add(str(predicate), 'app_features')

        extracted_ports = result.get('web_ports', set())
        if isinstance(extracted_ports, set):
            self._web_ports.update(extracted_ports)

        if self._app_feature_stats:
            print(
                "    [AppFeatures] "
                f"files={self._app_feature_stats.get('files_scanned', 0)} "
                f"frameworks={self._app_feature_stats.get('frameworks', 0)} "
                f"db_types={self._app_feature_stats.get('database_types', 0)} "
                f"routes={self._app_feature_stats.get('routes', 0)}"
            )

    def _add(self, predicate: str, category: str = 'unknown',
             metadata: Optional[Dict[str, Any]] = None):
        """Add a predicate if not already present."""
        if predicate not in self.seen_predicates:
            pred_obj = Predicate(predicate, category, metadata)
            self.predicates.append(pred_obj)
            self.seen_predicates.add(predicate)

    def add_network_context(self, attacker_location: str = 'internet'):
        """Add network topology predicates."""
        host_s = ScannerStrategy.sanitize(self.host)
        loc_s = ScannerStrategy.sanitize(attacker_location)

        self._add(f"attacker_at({loc_s}).", 'network_topology')
        self._add(f"host({host_s}).", 'network_topology')

    def detect_web_context(self):
        """
        Infer web application context from discovered services.
        Generates predicates that activate web security assessment rules.
        """
        for svc in self._services:
            svc_name = svc.get('service', '').lower()
            port = svc.get('port', 0)
            host = svc.get('host', self.host)
            host_s = ScannerStrategy.sanitize(host)

            is_web = (
                svc_name in WEB_SERVICES
                or int(port) in WEB_PORTS
            )

            if is_web:
                self._web_ports.add(int(port))
                # Emit web service predicate
                product = svc.get('product', svc_name)
                self._add(
                    f"web_service({host_s}, {port}, {ScannerStrategy.sanitize(product)}).",
                    'web_context'
                )
                # Web services likely have user input
                self._add(
                    f"has_user_input({host_s}, {port}, 'http_params').",
                    'web_context'
                )
                # If express/node/django/flask -> likely has API endpoints, login, upload
                # Check both service name and product name for framework detection
                combined = f"{svc_name} {product}".lower()
                if any(x in combined for x in ['express', 'node', 'flask', 'django', 'rails']):
                    self._add(
                        f"has_api_endpoint({host_s}, {port}, 'POST', '/api').",
                        'web_context'
                    )
                    self._add(
                        f"has_login_form({host_s}, {port}).",
                        'web_context'
                    )
                    self._add(
                        f"has_file_upload({host_s}, {port}).",
                        'web_context'
                    )

            # Database detection
            if svc_name in DATABASE_SERVICES:
                self._add(
                    f"uses_database({host_s}, {port}, {ScannerStrategy.sanitize(svc_name)}).",
                    'web_context'
                )
                self._add(
                    f"has_data({host_s}, 'database_records').",
                    'data_context'
                )

            # Auth service detection
            if svc_name in AUTH_SERVICES:
                self._add(
                    f"auth_service({host_s}, {port}, {ScannerStrategy.sanitize(svc_name)}).",
                    'auth_context'
                )

    def generate_attack_goals(self) -> List[str]:
        """
        Terminal goals for the integrated KB. execCode is the MulVAL standard goal (required
        by the attack_graph renderer and the quality metrics); compromise covers the web
        terminal, including the flag-localized compromise(_, flag_*) variants.

        recon_complete is queried too so a graph is ALWAYS produced: when no exploitation
        evidence is found, the reconnaissance / attack-surface subtree (exposed services, web
        fingerprint, detected weaknesses) still renders, giving the agent a high-level map of
        where to start instead of an empty file. It is derivable from base facts that exist
        whenever the target is reachable, and never chains into compromise/execCode, so it
        cannot be mistaken for a confirmed exploit path.
        """
        host_s = ScannerStrategy.sanitize(self.host)
        return [
            f"attackGoal(execCode({host_s}, _)).",
            f"attackGoal(compromise({host_s}, _)).",
            f"attackGoal(recon_complete({host_s}, _)).",
        ]

    def write_predicates(self, output_file: str):
        """Write all predicates to output file with contextual goals."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Detect web context from services
        self.detect_web_context()

        # Generate goals
        goals = self.generate_attack_goals()

        with open(output_file, 'w') as f:
            f.write("% ====================================================================\n")
            f.write("% MulVAL Input Predicates\n")
            f.write("% Generated by Strategy-based Scanner Parser\n")
            f.write(f"% Target Host: {self.host}\n")
            scanners = sorted(self._parsed_scanners) if self._parsed_scanners else sorted(self.strategies.keys())
            f.write(f"% Scanners: {', '.join(scanners)}\n")
            f.write("% ====================================================================\n\n")

            # Group predicates by category
            categories: Dict[str, List[Predicate]] = {}
            for pred in self.predicates:
                cat = pred.category
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(pred)

            # Write in a logical order
            order = [
                'network_topology', 'services', 'os_info', 'roles',
                'web_context', 'auth_context', 'data_context',
                'critical_cves', 'exploits', 'service_cve_correlation',
            ]
            written_cats: Set[str] = set()

            for cat in order:
                if cat in categories:
                    preds = categories[cat]
                    title = cat.replace('_', ' ').title()
                    f.write(f"\n% === {title} ===\n")
                    for pred in preds:
                        f.write(str(pred) + "\n")
                    written_cats.add(cat)

            # Write any remaining categories
            for cat, preds in sorted(categories.items()):
                if cat not in written_cats and preds:
                    title = cat.replace('_', ' ').title()
                    f.write(f"\n% === {title} ===\n")
                    for pred in preds:
                        f.write(str(pred) + "\n")

            # Attack goals
            f.write("\n% === Attack Goals ===\n")
            for goal in goals:
                f.write(goal + "\n")

        total = len(self.predicates) + len(goals)
        print(f"\n[+] Generated {total} predicates in {output_file}")
        self._print_statistics()

    def _print_statistics(self):
        """Print summary statistics."""
        stats = self.get_all_statistics()
        if stats:
            print("\n[Statistics]")
            for scanner, scanner_stats in stats.items():
                print(f"  {scanner}: {scanner_stats.get('total_predicates', 0)} predicates")

    def get_all_statistics(self) -> Dict[str, Dict[str, int]]:
        """Get statistics from all registered strategies."""
        return {
            name: strategy.get_statistics()
            for name, strategy in self.strategies.items()
        }
