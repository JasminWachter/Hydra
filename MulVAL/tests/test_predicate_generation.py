#!/usr/bin/env python3
"""
Unit tests for the refactored predicate generation pipeline.
Tests parser strategies, aggregator, and web context detection.
"""
import json
import sys
from pathlib import Path

import pytest

# Add parsers directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'parsers'))

from base_parser import Predicate, ScannerStrategy, PredicateAggregator
from trivy_parser_strategy import TrivyParserStrategy, MAX_CVES
from nmap_parser_strategy import NmapParserStrategy
from semgrep_parser_strategy import SemgrepParserStrategy
from scanner_strategy_factory import ScannerStrategyFactory
from app_feature_extractor import AppFeatureExtractor


# ────────────────────────────── Fixtures ──────────────────────────────

@pytest.fixture
def nmap_xml_express_mongo(tmp_path):
    """Nmap XML with Express on 3000 and MongoDB on 27017 (matches test-ctf)."""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000010">
  <status state="up"/>
  <address addr="192.168.3.15" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="9.6p1"/>
    </port>
    <port protocol="tcp" portid="3000">
      <state state="open"/>
      <service name="http" product="Node.js Express framework" version="5.1.0"/>
      <script id="http-title" output="TaskRunner"/>
    </port>
    <port protocol="tcp" portid="27017">
      <state state="open"/>
      <service name="mongodb" product="MongoDB" version="5.0.31"/>
      <script id="mongodb-info" output="authentication disabled"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 5.4" accuracy="95"/>
  </os>
</host>
</nmaprun>"""
    f = tmp_path / "nmap_results.xml"
    f.write_text(xml)
    return str(f)


@pytest.fixture
def trivy_json_critical(tmp_path):
    """Trivy JSON with a mix of CRITICAL, HIGH, MEDIUM, LOW CVEs."""
    data = {
        "Results": [{
            "Vulnerabilities": [
                # CRITICAL - should be included
                {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl",
                 "InstalledVersion": "1.1.1", "Severity": "CRITICAL",
                 "Description": "Critical OpenSSL vuln"},
                # HIGH - should be included
                {"VulnerabilityID": "CVE-2024-0002", "PkgName": "nodejs",
                 "InstalledVersion": "18.0.0", "Severity": "HIGH",
                 "Description": "Node.js high vuln"},
                # MEDIUM - should be EXCLUDED
                {"VulnerabilityID": "CVE-2024-0003", "PkgName": "curl",
                 "InstalledVersion": "7.80.0", "Severity": "MEDIUM",
                 "Description": "Medium curl vuln"},
                # LOW - should be EXCLUDED
                {"VulnerabilityID": "CVE-2024-0004", "PkgName": "zlib",
                 "InstalledVersion": "1.2.11", "Severity": "LOW",
                 "Description": "Low zlib vuln"},
                # Another CRITICAL
                {"VulnerabilityID": "CVE-2024-0005", "PkgName": "sqlite",
                 "InstalledVersion": "3.38.0", "Severity": "CRITICAL",
                 "Description": "Critical SQLite vuln"},
            ]
        }]
    }
    f = tmp_path / "trivy_results.json"
    f.write_text(json.dumps(data))
    return str(f)


@pytest.fixture
def trivy_json_many_cves(tmp_path):
    """Trivy JSON with >MAX_CVES critical CVEs to test limiting."""
    vulns = []
    for i in range(50):
        vulns.append({
            "VulnerabilityID": f"CVE-2024-{i:04d}",
            "PkgName": f"pkg{i}",
            "InstalledVersion": "1.0",
            "Severity": "CRITICAL",
            "Description": f"Critical vuln {i}",
        })
    data = {"Results": [{"Vulnerabilities": vulns}]}
    f = tmp_path / "trivy_many.json"
    f.write_text(json.dumps(data))
    return str(f)


@pytest.fixture
def semgrep_json_findings(tmp_path):
    data = {
        "results": [
            {"check_id": "python.flask.security.audit.xss.direct-response", "path": "app.py", "extra": {"severity": "WARNING"}},
            {"check_id": "javascript.express.security.audit.command-injection.child-process", "path": "routes.js", "extra": {"severity": "ERROR"}},
        ]
    }
    f = tmp_path / "semgrep_results.json"
    f.write_text(json.dumps(data))
    return str(f)


@pytest.fixture
def semgrep_json_realistic_findings(tmp_path):
    data = {
        "results": [
            {
                "check_id": "python.flask.security.injection.raw-html-concat.raw-html-format",
                "path": "server.py",
                "extra": {
                    "severity": "WARNING",
                    "message": "User input flows into manually constructed HTML string",
                    "metadata": {
                        "vulnerability_class": ["Cross-Site-Scripting (XSS)"],
                        "owasp": ["A03:2021 - Injection"],
                    },
                },
            },
            {
                "check_id": "generic.security.audit.path-traversal.user-controlled-path",
                "path": "handlers.py",
                "extra": {
                    "severity": "ERROR",
                    "message": "Potential path traversal using user-controlled path",
                    "metadata": {
                        "vulnerability_class": ["Path Traversal"],
                    },
                },
            },
        ]
    }
    f = tmp_path / "semgrep_realistic_results.json"
    f.write_text(json.dumps(data))
    return str(f)


@pytest.fixture
def aggregator():
    """Fresh PredicateAggregator for testing."""
    agg = PredicateAggregator(host='test_host')
    for scanner_type in ScannerStrategyFactory.get_available_scanners():
        strategy = ScannerStrategyFactory.create_strategy(scanner_type, host='test_host')
        agg.register_strategy(scanner_type, strategy)
    return agg


@pytest.fixture
def app_source_tree(tmp_path):
    """Minimal web app source tree for static feature extraction."""
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    (tmp_path / "Dockerfile").write_text("FROM node:20\nEXPOSE 3000\n")
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "demo",
                "dependencies": {
                    "express": "^4.0.0",
                    "mongoose": "^8.0.0",
                    "jsonwebtoken": "^9.0.0",
                    "multer": "^1.4.0",
                },
            }
        )
    )
    (tmp_path / "src" / "app.js").write_text(
        """
        const express = require('express');
        const app = express();
        app.post('/api/login', (req, res) => {
          const user = req.body.username;
          res.cookie('sid', 'abc');
          res.send(user);
        });
        app.post('/upload', upload.single('file'), (req, res) => res.send('ok'));
        """
    )
    return tmp_path


@pytest.fixture
def custom_signal_config(tmp_path):
    cfg = {
        "framework_signals": {"customfw": ["my-custom-framework"]},
        "database_signals": {"customdb": ["customdb://"]},
        "feature_signals": {
            "user_input": ["custom_input"],
            "login": ["custom_login"],
            "cookie_auth": ["custom_cookie"],
            "file_upload": ["custom_upload"],
        },
        "api_route_patterns": [r"custom_route\((get|post),\s*'([^']+)'"],
        "port_patterns": {
            "dockerfile_expose": r"EXPOSE\s+(\d{2,5})",
            "compose_mapping": r"(\d{2,5}):(\d{2,5})",
            "env_port": r"PORT=(\d{2,5})",
        },
    }
    config_path = tmp_path / "signals.json"
    config_path.write_text(json.dumps(cfg), encoding="utf-8")
    return config_path


# ────────────────────────────── Predicate class ──────────────────────

class TestPredicate:
    def test_string_representation(self):
        p = Predicate("service('h', 80, tcp, 'http', '1.0').", 'services')
        assert str(p) == "service('h', 80, tcp, 'http', '1.0')."

    def test_deduplication(self):
        p1 = Predicate("vuln('h', 'CVE-1', pkg).", 'cves')
        p2 = Predicate("vuln('h', 'CVE-1', pkg).", 'cves')
        assert p1 == p2
        assert hash(p1) == hash(p2)
        assert len({p1, p2}) == 1


# ────────────────────────────── Nmap Parser ──────────────────────────

class TestNmapParser:
    def test_parses_services(self, nmap_xml_express_mongo):
        parser = NmapParserStrategy(host='test')
        predicates = parser.parse(nmap_xml_express_mongo)
        pred_strs = [str(p) for p in predicates]

        # Should detect SSH, HTTP (Express), MongoDB
        assert any("service(" in p and "'ssh'" in p for p in pred_strs)
        assert any("service(" in p and "'http'" in p and "3000" in p for p in pred_strs)
        assert any("service(" in p and "'mongodb'" in p for p in pred_strs)

    def test_generates_connectivity(self, nmap_xml_express_mongo):
        parser = NmapParserStrategy(host='test')
        predicates = parser.parse(nmap_xml_express_mongo)
        pred_strs = [str(p) for p in predicates]

        # Should have connects() and exposed() for all open ports
        assert any("connects(" in p and "3000" in p for p in pred_strs)
        assert any("exposed(" in p and "3000" in p for p in pred_strs)
        assert any("connects(" in p and "27017" in p for p in pred_strs)

    def test_detects_roles(self, nmap_xml_express_mongo):
        parser = NmapParserStrategy(host='test')
        predicates = parser.parse(nmap_xml_express_mongo)
        pred_strs = [str(p) for p in predicates]

        assert any("role(" in p and "'webserver'" in p for p in pred_strs)
        assert any("role(" in p and "'database'" in p for p in pred_strs)
        assert any("role(" in p and "'ssh_server'" in p for p in pred_strs)

    def test_no_os_detection(self, nmap_xml_express_mongo):
        # The scan command doesn't run -O (needs raw sockets/root, not reliably available),
        # so <osmatch> is never present in the XML and os() must never be emitted.
        parser = NmapParserStrategy(host='test')
        predicates = parser.parse(nmap_xml_express_mongo)
        pred_strs = [str(p) for p in predicates]

        assert not any(p.startswith("os(") for p in pred_strs)

    def test_mongodb_no_auth_detection(self, nmap_xml_express_mongo):
        parser = NmapParserStrategy(host='test')
        predicates = parser.parse(nmap_xml_express_mongo)
        pred_strs = [str(p) for p in predicates]

        # mongodb-info script says "authentication disabled"
        assert any("no_auth_required(" in p and "27017" in p for p in pred_strs)

    def test_stores_services_for_correlation(self, nmap_xml_express_mongo):
        parser = NmapParserStrategy(host='test')
        parser.parse(nmap_xml_express_mongo)

        assert len(parser.services) == 3
        service_names = [s['service'] for s in parser.services]
        assert 'ssh' in service_names
        assert 'http' in service_names
        assert 'mongodb' in service_names

    def test_web_ports_tracked(self, nmap_xml_express_mongo):
        parser = NmapParserStrategy(host='test')
        parser.parse(nmap_xml_express_mongo)

        assert 3000 in parser.web_ports

    def test_data_presence_for_database(self, nmap_xml_express_mongo):
        parser = NmapParserStrategy(host='test')
        predicates = parser.parse(nmap_xml_express_mongo)
        pred_strs = [str(p) for p in predicates]

        assert any("has_data(" in p for p in pred_strs)

    def test_invalid_xml(self, tmp_path):
        f = tmp_path / "bad.xml"
        f.write_text("not xml at all")
        parser = NmapParserStrategy(host='test')
        result = parser.parse(str(f))
        assert result == []

    def test_closed_ports_excluded(self, tmp_path):
        xml = """<?xml version="1.0"?>
<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
  <state state="closed"/>
  <service name="http"/>
</port>
</ports></host></nmaprun>"""
        f = tmp_path / "nmap_closed.xml"
        f.write_text(xml)
        parser = NmapParserStrategy(host='test')
        predicates = parser.parse(str(f))
        pred_strs = [str(p) for p in predicates]
        # No service predicate for closed port
        assert not any("service(" in p and "80" in p for p in pred_strs)


# ────────────────────────────── Trivy Parser ─────────────────────────

class TestTrivyParser:
    def test_filters_medium_and_low(self, trivy_json_critical):
        parser = TrivyParserStrategy(host='test')
        predicates = parser.parse(trivy_json_critical)
        pred_strs = [str(p) for p in predicates]

        # CRITICAL and HIGH should be present
        assert any("CVE-2024-0001" in p for p in pred_strs)
        assert any("CVE-2024-0002" in p for p in pred_strs)
        # MEDIUM and LOW should be excluded
        assert not any("CVE-2024-0003" in p for p in pred_strs)
        assert not any("CVE-2024-0004" in p for p in pred_strs)

    def test_exploit_possible_for_critical(self, trivy_json_critical):
        parser = TrivyParserStrategy(host='test')
        predicates = parser.parse(trivy_json_critical)
        pred_strs = [str(p) for p in predicates]

        # exploit_possible only for CRITICAL
        assert any("exploit_possible(" in p and "CVE-2024-0001" in p for p in pred_strs)
        assert any("exploit_possible(" in p and "CVE-2024-0005" in p for p in pred_strs)
        # NOT for HIGH
        assert not any("exploit_possible(" in p and "CVE-2024-0002" in p for p in pred_strs)

    def test_limits_to_max_cves(self, trivy_json_many_cves):
        parser = TrivyParserStrategy(host='test')
        predicates = parser.parse(trivy_json_many_cves)

        vuln_preds = [p for p in predicates if 'vuln(' in str(p)]
        assert len(vuln_preds) <= MAX_CVES

    def test_produces_vuln_3_predicate(self, trivy_json_critical):
        parser = TrivyParserStrategy(host='test')
        predicates = parser.parse(trivy_json_critical)
        pred_strs = [str(p) for p in predicates]

        # vuln/3 format: vuln(host, cve_id, package)
        assert any(p.startswith("vuln(") for p in pred_strs)

    def test_stores_cves_for_correlation(self, trivy_json_critical):
        parser = TrivyParserStrategy(host='test')
        parser.parse(trivy_json_critical)

        # Should store CVE data for cross-scanner correlation
        assert len(parser.cves) > 0
        assert all('cve_id' in c for c in parser.cves)

    def test_invalid_json(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json")
        parser = TrivyParserStrategy(host='test')
        result = parser.parse(str(f))
        assert result == []


class TestSemgrepParser:
    @staticmethod
    def _write(tmp_path, results):
        f = tmp_path / "semgrep_results.json"
        f.write_text(json.dumps({"results": results}))
        return str(f)

    def test_emits_localized_taint_flow(self, tmp_path):
        results = [{
            "check_id": "ssrf-user-input-to-fetcher", "path": "/src/report.php",
            "start": {"line": 18},
            "extra": {"lines": "exec($command)",
                      "metadata": {"vuln_class": "ssrf", "cwe": ["CWE-918"]}},
        }]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        # taint_flow(Host, Port, Param, File, Line, Class, Sink) — localized to file:line
        assert any(p.startswith("taint_flow('test'") and "ssrf" in p
                   and "'report.php'" in p and ", 18," in p for p in preds)

    def test_emits_cookie_flag_but_not_source_flag(self, tmp_path):
        # A cookie-delivered flag is a legitimate (exploit-gated) target; a flag literal
        # hardcoded in source is a redacted placeholder and must NOT become a flag_location.
        results = [
            {"check_id": "flag-in-cookie", "path": "/src/view.php", "start": {"line": 4},
             "extra": {"lines": 'setcookie("flag", $x)',
                       "metadata": {"vuln_class": "flag_cookie"}}},
            {"check_id": "flag-literal-in-source", "path": "/src/index.php", "start": {"line": 138},
             "extra": {"lines": "hkcert20{redacted_example_flag}",
                       "metadata": {"vuln_class": "flag_source_code"}}},
        ]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        assert any(p.startswith("flag_location('test', cookie, 'flag'") for p in preds)
        assert not any("source_code" in p for p in preds)

    def test_emits_access_gate(self, tmp_path):
        results = [{
            "check_id": "localhost-only-gate", "path": "/src/view.php", "start": {"line": 2},
            "extra": {"lines": "$_SERVER...", "metadata": {"vuln_class": "gate_localhost_only"}},
        }]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        assert any(p.startswith("access_gate('test',") and "localhost_only" in p for p in preds)

    def test_localizes_js_taint_param_and_sink(self, tmp_path):
        # A non-PHP (JS/Express) flow must still localize with the request param and sink.
        results = [{
            "check_id": "js-cmdi-user-input-to-shell", "path": "/src/routes.js",
            "start": {"line": 42},
            "extra": {"lines": "child_process.exec(req.query.host)",
                      "metadata": {"vuln_class": "cmdi", "cwe": ["CWE-78"]}},
        }]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        assert any(p.startswith("taint_flow('test'") and "cmdi" in p
                   and "'routes.js'" in p and ", 42," in p
                   and "'host'" in p and "child_process.exec" in p for p in preds)

    def test_localizes_python_taint_param(self, tmp_path):
        results = [{
            "check_id": "py-ssti-user-input-to-template", "path": "/src/app.py",
            "start": {"line": 10},
            "extra": {"lines": "render_template_string(request.args.get('name'))",
                      "metadata": {"vuln_class": "ssti"}},
        }]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        assert any(p.startswith("taint_flow('test'") and "'name'" in p
                   and "render_template_string" in p for p in preds)

    def test_localizes_java_taint_param(self, tmp_path):
        results = [{
            "check_id": "java-sqli-user-input-to-statement", "path": "/src/App.java",
            "start": {"line": 88},
            "extra": {"lines": 'stmt.executeQuery(request.getParameter("id"))',
                      "metadata": {"vuln_class": "sqli"}},
        }]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        assert any(p.startswith("taint_flow('test'") and "'id'" in p
                   and "executeQuery" in p for p in preds)

    def test_excludes_solution_and_metadata_findings(self, tmp_path):
        results = [
            {"check_id": "py-cmdi-user-input-to-shell", "path": "/src/solution/exploit.py",
             "start": {"line": 3}, "extra": {"lines": "os.system(x)",
                                              "metadata": {"vuln_class": "cmdi"}}},
            {"check_id": "py-cmdi-user-input-to-shell", "path": "/src/metadata/solution/x.py",
             "start": {"line": 3}, "extra": {"lines": "os.system(x)",
                                              "metadata": {"vuln_class": "cmdi"}}},
            {"check_id": "js-cmdi-user-input-to-shell", "path": "/src/app/routes.js",
             "start": {"line": 5}, "extra": {"lines": "child_process.exec(req.query.c)",
                                              "metadata": {"vuln_class": "cmdi"}}},
        ]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        assert not any("exploit.py" in p for p in preds)
        assert not any("solution" in p for p in preds)
        assert any("routes.js" in p for p in preds)

    def test_heuristic_finding_emits_sink_evidence_not_taint_flow(self, tmp_path):
        # A tier-2 heuristic finding (dangerous sink shape, no proven dataflow) must emit only
        # sink_evidence — never taint_flow or detected_vuln, so it cannot borrow tier-1 confidence.
        results = [{
            "check_id": "py-heuristic-sqli-dynamic-query", "path": "/src/app.py",
            "start": {"line": 27},
            "extra": {"lines": "cur.execute(f\"SELECT * FROM t WHERE id={request.args.get('id')}\")",
                      "metadata": {"vuln_class": "sqli", "evidence_tier": "heuristic"}},
        }]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        assert any(p.startswith("sink_evidence('test'") and "sqli" in p
                   and "'app.py'" in p and ", 27," in p for p in preds)
        assert not any(p.startswith("taint_flow(") for p in preds)
        assert not any(p.startswith("detected_vuln(") for p in preds)

    def test_proven_taint_finding_still_emits_taint_flow_and_detected_vuln(self, tmp_path):
        # A normal (non-heuristic) finding keeps the tier-1 behavior unchanged.
        results = [{
            "check_id": "py-cmdi-user-input-to-shell", "path": "/src/app.py",
            "start": {"line": 9},
            "extra": {"lines": "os.system(request.args.get('c'))",
                      "metadata": {"vuln_class": "cmdi"}},
        }]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        assert any(p.startswith("taint_flow('test'") and "cmdi" in p for p in preds)
        assert any(p.startswith("detected_vuln('test'") and "cmdi" in p for p in preds)
        assert not any(p.startswith("sink_evidence(") for p in preds)

    def test_does_not_exclude_metadata_challenge_source(self, tmp_path):
        # metadata/challenge/... is a real deployed build context for some tasks (e.g. the
        # sekai frog-waf layout) and must stay scannable - only metadata/solution etc. is cut.
        results = [{
            "check_id": "java-sqli-user-input-to-statement",
            "path": "/src/metadata/challenge/src/main/App.java",
            "start": {"line": 20},
            "extra": {"lines": 'stmt.executeQuery(request.getParameter("id"))',
                      "metadata": {"vuln_class": "sqli"}},
        }]
        parser = SemgrepParserStrategy(host='test')
        preds = [str(p) for p in parser.parse(self._write(tmp_path, results))]

        assert any("App.java" in p for p in preds)


# ────────────────────────────── Factory ──────────────────────────────

class TestScannerStrategyFactory:
    def test_available_scanners(self):
        available = ScannerStrategyFactory.get_available_scanners()
        assert 'trivy' in available
        assert 'nmap' in available
        assert 'semgrep' in available
        assert 'grype' not in available
        # AppInspector should be removed
        assert 'appinspector' not in available

    def test_create_trivy(self):
        s = ScannerStrategyFactory.create_strategy('trivy')
        assert isinstance(s, TrivyParserStrategy)

    def test_create_nmap(self):
        s = ScannerStrategyFactory.create_strategy('nmap')
        assert isinstance(s, NmapParserStrategy)

    def test_unknown_scanner_raises(self):
        with pytest.raises(ValueError, match="Unknown scanner"):
            ScannerStrategyFactory.create_strategy('appinspector')


# ────────────────────────────── Aggregator ───────────────────────────

class TestPredicateAggregator:
    def test_network_context(self, aggregator):
        aggregator.add_network_context(attacker_location='internet')
        pred_strs = [str(p) for p in aggregator.predicates]

        assert "attacker_at('internet')." in pred_strs
        assert "host('test_host')." in pred_strs

    def test_web_context_detection(self, aggregator, nmap_xml_express_mongo):
        """After parsing nmap with Express, web context should be detected."""
        aggregator.parse_all({'nmap': nmap_xml_express_mongo})
        aggregator.detect_web_context()
        pred_strs = [str(p) for p in aggregator.predicates]

        # Should have web_service for port 3000
        assert any("web_service(" in p and "3000" in p for p in pred_strs)
        # Should have uses_database for MongoDB
        assert any("uses_database(" in p and "27017" in p and "'mongodb'" in p
                    for p in pred_strs)
        # Should have auth_service for SSH
        assert any("auth_service(" in p and "22" in p for p in pred_strs)

    def test_semgrep_taint_flow_joins_nmap_web_port(self, aggregator, nmap_xml_express_mongo, tmp_path):
        """taint_flow must land on nmap's discovered web port (3000), not semgrep's own
        compose-based guess, so the localized *_confirmed -> initial_access chain can join
        against connects/web_service on the same port."""
        semgrep_results = tmp_path / "semgrep_results.json"
        semgrep_results.write_text(json.dumps({"results": [{
            "check_id": "js-cmdi-user-input-to-shell", "path": "/src/routes.js",
            "start": {"line": 5},
            "extra": {"lines": "child_process.exec(req.query.c)",
                      "metadata": {"vuln_class": "cmdi"}},
        }]}))

        # Parse order deliberately puts semgrep before nmap in the input dict to prove
        # parse_all's ordering (not dict insertion order) drives the port hint.
        aggregator.parse_all({'semgrep': str(semgrep_results), 'nmap': nmap_xml_express_mongo})
        pred_strs = [str(p) for p in aggregator.predicates]

        assert any("taint_flow(" in p and ", 3000," in p for p in pred_strs)
        assert any(p.startswith("connects(") and "3000" in p for p in pred_strs)

    def test_web_context_framework_inferrence(self, aggregator, nmap_xml_express_mongo):
        """Express should trigger web features, but not infer cookie authentication."""
        aggregator.parse_all({'nmap': nmap_xml_express_mongo})
        aggregator.detect_web_context()
        pred_strs = [str(p) for p in aggregator.predicates]

        # Express framework detection should infer these
        assert any("has_user_input(" in p for p in pred_strs)
        assert any("has_login_form(" in p for p in pred_strs)
        assert any("has_api_endpoint(" in p for p in pred_strs)
        assert any("has_file_upload(" in p for p in pred_strs)
        # A framework fingerprint does not prove how the application authenticates.
        # has_cookie_auth is emitted only from supporting source-analysis evidence.
        assert not any("has_cookie_auth(" in p for p in pred_strs)

    def test_attack_goals_are_execcode_and_compromise(self, aggregator, nmap_xml_express_mongo):
        """Integrated KB terminal goals: execCode (MulVAL standard) and compromise."""
        aggregator.parse_all({'nmap': nmap_xml_express_mongo})
        aggregator.detect_web_context()
        goals = aggregator.generate_attack_goals()

        goal_strs = [str(g) for g in goals]
        assert any("attackGoal(execCode(" in g for g in goal_strs)
        assert any("attackGoal(compromise(" in g for g in goal_strs)

    def test_cross_scanner_correlation(self, aggregator, nmap_xml_express_mongo,
                                        trivy_json_critical):
        """CVEs from Trivy should be correlated with services from Nmap."""
        aggregator.parse_all({
            'nmap': nmap_xml_express_mongo,
            'trivy': trivy_json_critical,
        })
        # After correlation, remote_service_vulnerable might be created
        # (depends on whether CVE packages match discovered services)
        pred_strs = [str(p) for p in aggregator.predicates]

        # Check that both scanner outputs were parsed
        assert any("service(" in p for p in pred_strs)
        assert any("vuln(" in p for p in pred_strs)

    def test_write_predicates(self, aggregator, nmap_xml_express_mongo, tmp_path):
        """Write predicates to file and verify structure."""
        aggregator.parse_all({'nmap': nmap_xml_express_mongo})
        aggregator.add_network_context()

        out_file = tmp_path / "input_predicates.P"
        aggregator.write_predicates(str(out_file))

        content = out_file.read_text()

        # Should have section headers
        assert "% === Network Topology ===" in content or "% ===" in content
        # Should have attack goals
        assert "attackGoal(" in content
        # Should not be empty
        assert len(content.strip()) > 100

    def test_predicate_deduplication(self, aggregator):
        """Same predicate added twice should only appear once."""
        aggregator._add("host('test').", 'network')
        aggregator._add("host('test').", 'network')
        host_preds = [p for p in aggregator.predicates if "host('test')" in str(p)]
        assert len(host_preds) == 1

    def test_total_predicates_under_limit(self, aggregator, nmap_xml_express_mongo,
                                           trivy_json_critical):
        """Total predicates should stay reasonable (not hundreds of CVEs)."""
        aggregator.parse_all({
            'nmap': nmap_xml_express_mongo,
            'trivy': trivy_json_critical,
        })
        aggregator.add_network_context()
        aggregator.detect_web_context()

        # With our MAX_CVES=20 cap and context detection,
        # total should be well under 100 (not 1000+ like before)
        total = len(aggregator.predicates)
        assert total < 100, f"Too many predicates: {total}"
        assert total > 10, f"Too few predicates: {total} (parsing may have failed)"

    def test_app_feature_extractor_emits_web_activation_predicates(
        self, aggregator, app_source_tree
    ):
        aggregator.add_app_features(str(app_source_tree))
        pred_strs = [str(p) for p in aggregator.predicates]

        assert any("connects('internet'" in p and "3000" in p for p in pred_strs)
        assert any("service(" in p and "'inferred'" in p and "3000" in p for p in pred_strs)
        assert any("web_service(" in p and "3000" in p for p in pred_strs)
        assert any("has_api_endpoint(" in p and "'/api/login'" in p for p in pred_strs)
        assert any("has_login_form(" in p for p in pred_strs)
        assert any("has_cookie_auth(" in p for p in pred_strs)
        assert any("has_file_upload(" in p for p in pred_strs)
        assert any("uses_database(" in p and "'mongodb'" in p for p in pred_strs)
        # AppFeatureExtractor no longer infers vulnerabilities from regex co-occurrence -
        # detected_vuln must come only from localized Semgrep taint findings.
        assert not any("detected_vuln(" in p for p in pred_strs)

    def test_trivy_only_plus_app_features_still_generates_goals(
        self, aggregator, trivy_json_critical, app_source_tree
    ):
        aggregator.parse_all({'trivy': trivy_json_critical})
        aggregator.add_app_features(str(app_source_tree))
        goals = aggregator.generate_attack_goals()
        goal_strs = [str(g) for g in goals]

        assert any("attackGoal(execCode(" in g for g in goal_strs)

    def test_config_driven_extractor_accepts_custom_patterns(self, tmp_path, custom_signal_config):
        app_root = tmp_path / "custom_app"
        app_root.mkdir(parents=True, exist_ok=True)
        (app_root / "Dockerfile").write_text("FROM scratch\nEXPOSE 9090\n", encoding="utf-8")
        (app_root / "main.txt").write_text(
            "my-custom-framework customdb:// local custom_input custom_login custom_cookie "
            "custom_upload custom_route(post, '/custom')",
            encoding="utf-8",
        )

        extractor = AppFeatureExtractor(config_path=custom_signal_config)
        result = extractor.extract(
            target_dir=app_root,
            host_atom="'h'",
            candidate_ports=[],
        )
        pred_str = "\n".join(result["predicates"])

        assert "web_framework('h', 9090, 'customfw')." in pred_str
        assert "uses_database('h', 9090, 'customdb')." in pred_str
        assert "has_api_endpoint('h', 9090, 'POST', '/custom')." in pred_str


# ────────────────────────────── Sanitization ─────────────────────────

class TestSanitization:
    def test_sanitize_wraps_in_quotes(self):
        assert ScannerStrategy.sanitize("hello") == "'hello'"

    def test_sanitize_removes_single_quotes(self):
        assert ScannerStrategy.sanitize("it's") == "'its'"

    def test_atom_lowercases(self):
        assert ScannerStrategy.atom("OpenSSH") == "openssh"

    def test_atom_replaces_special_chars(self):
        assert ScannerStrategy.atom("node-js") == "node_js"
        assert ScannerStrategy.atom("1.2.3") == "1_2_3"


if __name__ == '__main__':
    pytest.exit(pytest.main([__file__, '-v']))
