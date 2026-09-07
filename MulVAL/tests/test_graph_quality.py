#!/usr/bin/env python3
"""
Tests for graph quality - validates that generated predicates activate
the web security interaction rules and produce multi-step attack paths.

These tests simulate the full predicate flow (scanner → aggregator → rules)
without requiring MulVAL/Docker -- they verify predicate-rule alignment.
"""
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / 'parsers'))
from base_parser import PredicateAggregator
from scanner_strategy_factory import ScannerStrategyFactory


# ────────────────────────────── Rule Parser ───────────────────────────

def load_interaction_rules(rules_file: str) -> list:
    """Parse interaction_rule/2 clauses from a Prolog file.
    Returns list of dicts: {head, body_preds, description, confidence}."""
    content = Path(rules_file).read_text()
    rules = []

    # Match: interaction_rule( (head :- body), rule_desc('...', N)).
    pattern = re.compile(
        r"interaction_rule\(\s*\(\s*(.+?)\s*:-\s*(.+?)\s*\)\s*,"
        r"\s*rule_desc\(\s*'([^']+)'\s*,\s*([\d.]+)\s*\)\s*\)",
        re.DOTALL,
    )

    for m in pattern.finditer(content):
        head = m.group(1).strip()
        body_raw = m.group(2).strip()
        desc = m.group(3)
        conf = float(m.group(4))

        # Extract predicate names from body (simple tokenisation)
        body_preds = []
        for token in re.findall(r'(\w+)\s*\(', body_raw):
            if token not in ('rule_desc',):
                body_preds.append(token)

        rules.append({
            'head': head,
            'body_raw': body_raw,
            'body_preds': body_preds,
            'description': desc,
            'confidence': conf,
        })

    return rules


# ────────────────────────────── Fixtures ──────────────────────────────

RULES_FILE = Path(__file__).parent.parent / 'kb' / 'web_security_rules.P'


@pytest.fixture
def web_rules():
    """Load web security interaction rules."""
    if not RULES_FILE.exists():
        pytest.skip("web_security_rules.P not found")
    return load_interaction_rules(str(RULES_FILE))


@pytest.fixture
def express_mongo_predicates(tmp_path):
    """Generate predicates for an Express+MongoDB target (like test-ctf)."""
    import json

    # Create nmap XML
    nmap_xml = """<?xml version="1.0"?>
<nmaprun>
<host>
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
  <os><osmatch name="Linux 5.4" accuracy="95"/></os>
</host>
</nmaprun>"""

    nmap_f = tmp_path / "nmap.xml"
    nmap_f.write_text(nmap_xml)

    # Create trivy JSON with a few critical CVEs
    trivy_data = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-9999", "PkgName": "openssl",
         "InstalledVersion": "1.1.1", "Severity": "CRITICAL",
         "Description": "OpenSSL critical"},
    ]}]}
    trivy_f = tmp_path / "trivy.json"
    trivy_f.write_text(json.dumps(trivy_data))

    # Run aggregator
    agg = PredicateAggregator(host='target')
    for stype in ScannerStrategyFactory.get_available_scanners():
        strategy = ScannerStrategyFactory.create_strategy(stype, host='target')
        agg.register_strategy(stype, strategy)

    agg.parse_all({'nmap': str(nmap_f), 'trivy': str(trivy_f)})
    agg.add_network_context(attacker_location='internet')
    agg.detect_web_context()
    goals = agg.generate_attack_goals()

    # Return all predicate functors
    all_preds = set()
    for p in agg.predicates:
        m = re.match(r'(\w+)\s*\(', str(p))
        if m:
            all_preds.add(m.group(1))
    for g in goals:
        m = re.match(r'attackGoal\((\w+)\(', g)
        if m:
            all_preds.add(m.group(1))

    return all_preds, agg.predicates, goals


# ────────────────────────────── Quality Tests ────────────────────────

class TestRuleStructure:
    """Validate the structure of web security rules."""

    def test_rules_load(self, web_rules):
        assert len(web_rules) > 30, f"Too few rules: {len(web_rules)}"

    def test_all_rules_have_descriptions(self, web_rules):
        for rule in web_rules:
            assert rule['description'], f"Rule missing description: {rule['head']}"

    def test_all_rules_have_confidence(self, web_rules):
        for rule in web_rules:
            assert 0 < rule['confidence'] <= 1.0, \
                f"Invalid confidence {rule['confidence']} for: {rule['head']}"

    def test_multi_step_paths_exist(self, web_rules):
        """At least some rules should have 2+ body predicates."""
        multi_body = [r for r in web_rules if len(r['body_preds']) >= 2]
        assert len(multi_body) > 10, \
            f"Too few multi-body rules: {len(multi_body)} (need complex paths)"

    def test_kill_chain_stages_covered(self, web_rules):
        """Rules should produce outputs at every kill-chain stage."""
        heads = set()
        for rule in web_rules:
            m = re.match(r'(\w+)\s*\(', rule['head'])
            if m:
                heads.add(m.group(1))

        expected = {
            'recon_complete', 'initial_access', 'exec_achieved',
            'compromise', 'cred_obtained',
        }
        missing = expected - heads
        assert not missing, f"Missing kill-chain stages: {missing}"

    def test_vulnerability_surfaces_covered(self, web_rules):
        """Rules should detect common vulnerability surfaces."""
        heads = set()
        for rule in web_rules:
            m = re.match(r'(\w+)\s*\(', rule['head'])
            if m:
                heads.add(m.group(1))

        expected_surfaces = {
            'sqli_surface', 'cmdi_surface', 'xss_surface',
            'auth_bypass_surface', 'path_traversal_surface',
        }
        missing = expected_surfaces - heads
        assert not missing, f"Missing vulnerability surfaces: {missing}"

    def test_vulnerability_confirmation_rules(self, web_rules):
        """Each vulnerability surface should have a confirmation rule."""
        heads = set()
        for rule in web_rules:
            m = re.match(r'(\w+)\s*\(', rule['head'])
            if m:
                heads.add(m.group(1))

        surfaces = {h for h in heads if h.endswith('_surface')}
        for surface in surfaces:
            confirmed = surface.replace('_surface', '_confirmed')
            assert confirmed in heads, \
                f"No confirmation rule for {surface} (expected {confirmed})"


class TestPredicateRuleAlignment:
    """Verify scanner predicates actually match what rules expect."""

    def test_scanner_produces_required_primitives(self, express_mongo_predicates):
        """Scanner predicates must include primitives the rules consume."""
        pred_functors, _, _ = express_mongo_predicates

        # Critical primitives that rules need
        required_primitives = {
            'attacker_at', 'host', 'connects', 'service', 'exposed',
        }
        missing = required_primitives - pred_functors
        assert not missing, f"Scanner doesn't produce required primitives: {missing}"

    def test_web_context_predicates_generated(self, express_mongo_predicates):
        """Express app should generate web context predicates."""
        pred_functors, _, _ = express_mongo_predicates

        expected_web = {
            'web_service', 'has_user_input', 'has_login_form',
            'has_api_endpoint',
        }
        missing = expected_web - pred_functors
        assert not missing, \
            f"Web context predicates missing: {missing}"
        assert 'has_cookie_auth' not in pred_functors, \
            "Nmap framework detection must not infer cookie authentication"

    def test_database_context_generated(self, express_mongo_predicates):
        """MongoDB should generate database predicates."""
        pred_functors, _, _ = express_mongo_predicates

        assert 'uses_database' in pred_functors, \
            "uses_database not generated for MongoDB"
        assert 'has_data' in pred_functors, \
            "has_data not generated for database host"

    def test_attack_goals_generated(self, express_mongo_predicates):
        """Terminal goal is a localized flag retrieval (dataflow-led KB)."""
        _, _, goals = express_mongo_predicates

        goal_str = ' '.join(goals)
        assert 'attackGoal(execCode(' in goal_str
        assert 'attackGoal(compromise(' in goal_str

    def test_auth_context_generated(self, express_mongo_predicates):
        """SSH and MongoDB should generate auth context."""
        pred_functors, _, _ = express_mongo_predicates

        assert 'auth_service' in pred_functors, \
            "auth_service not generated for SSH"

    def test_no_auth_required_for_mongodb(self, express_mongo_predicates):
        """MongoDB with 'authentication disabled' should emit no_auth_required."""
        pred_functors, all_preds, _ = express_mongo_predicates
        pred_strs = [str(p) for p in all_preds]

        assert any("no_auth_required(" in p and "27017" in p for p in pred_strs), \
            "no_auth_required not generated for MongoDB without auth"


class TestPathReachability:
    """
    Simulate rule activation to estimate path depth.
    This doesn't run XSB Prolog, but checks that rules can chain.
    """

    def test_sqli_path_depth(self, web_rules, express_mongo_predicates):
        """SQLi path should be at least 5 steps deep:
        recon → sqli_surface → sqli_confirmed → initial_access → exec/cred → compromise"""
        pred_functors, _, _ = express_mongo_predicates

        # Stage 1: recon_complete should be activatable
        recon_rules = [r for r in web_rules if r['head'].startswith('recon_complete')]
        recon_body_functors = set()
        for r in recon_rules:
            recon_body_functors.update(r['body_preds'])

        # Check some recon body predicates are in scanner output
        recon_possible = bool(recon_body_functors & pred_functors)
        assert recon_possible, \
            f"No recon rule body matches scanner predicates. " \
            f"Rule needs: {recon_body_functors}, scanner has: {pred_functors}"

        # Stage 2: sqli_surface depends on recon_complete + web_service + uses_database
        sqli_surface_rules = [r for r in web_rules
                              if r['head'].startswith('sqli_surface')]
        assert len(sqli_surface_rules) > 0, "No sqli_surface rules found"

        # Stage 3: sqli_confirmed depends on sqli_surface + has_user_input
        sqli_confirmed_rules = [r for r in web_rules
                                if r['head'].startswith('sqli_confirmed')]
        assert len(sqli_confirmed_rules) > 0, "No sqli_confirmed rules found"

        # Stage 4: initial_access depends on sqli_confirmed + connects
        initial_sqli = [r for r in web_rules
                        if 'initial_access' in r['head'] and 'sqli' in r['head']]
        assert len(initial_sqli) > 0, "No initial_access(Host, sqli, ...) rule found"

    def test_compromise_reachable_from_cmdi(self, web_rules):
        """Command injection chain: surface → confirmed → initial_access →
        exec_achieved → compromise"""
        heads = set()
        for rule in web_rules:
            m = re.match(r'(\w+)\s*\(', rule['head'])
            if m:
                heads.add(m.group(1))

        chain = ['cmdi_surface', 'cmdi_confirmed', 'initial_access',
                 'exec_achieved', 'compromise']
        for stage in chain:
            assert stage in heads, f"Missing stage in CMDi chain: {stage}"

    def test_nosqli_path_through_mongodb(self, web_rules, express_mongo_predicates):
        """NoSQL injection should be relevant when MongoDB is present."""
        pred_functors, _, _ = express_mongo_predicates

        # MongoDB present → uses_database should be in predicates
        assert 'uses_database' in pred_functors

        # NoSQL injection surface rule should exist
        nosqli_rules = [r for r in web_rules
                        if 'nosql_injection_surface' in r['head']]
        assert len(nosqli_rules) > 0

    def test_auth_bypass_requires_cookie_evidence(self, web_rules, express_mongo_predicates):
        """Cookie-based auth bypass remains gated on source-analysis evidence."""
        pred_functors, _, _ = express_mongo_predicates

        assert 'has_login_form' in pred_functors
        assert 'has_cookie_auth' not in pred_functors

        auth_bypass_rules = [r for r in web_rules
                             if 'auth_bypass_surface' in r['head']]
        cookie_auth_rules = [r for r in auth_bypass_rules
                             if 'has_cookie_auth' in r['body_preds']]
        assert cookie_auth_rules, \
            "Auth bypass rule should require explicit cookie-auth evidence"

    def test_minimum_expected_paths(self, web_rules, express_mongo_predicates):
        """For Express+MongoDB, we expect at least 5 different vulnerability
        surfaces to be testable."""
        pred_functors, _, _ = express_mongo_predicates

        # Count activatable surface rules
        activatable = 0
        surface_rules = [r for r in web_rules
                         if r['head'].split('(')[0].endswith('_surface')]

        for rule in surface_rules:
            body_functors = set(rule['body_preds'])
            # Rule is activatable if ALL body predicates are either
            # from scanner output or from derived predicates
            all_derived = {'recon_complete', 'sqli_surface', 'cmdi_surface',
                           'xss_surface', 'ssrf_surface', 'path_traversal_surface',
                           'auth_bypass_surface', 'nosql_injection_surface',
                           'upload_vuln_surface', 'deserialization_surface',
                           'xxe_surface', 'ssti_surface'}
            available = pred_functors | all_derived
            if body_functors.issubset(available):
                activatable += 1

        assert activatable >= 5, \
            f"Only {activatable} surfaces activatable (expected ≥5 for Express+MongoDB)"


class TestPredicateBloat:
    """Ensure we don't regress to 1000+ predicates."""

    def test_max_cve_predicates(self, express_mongo_predicates):
        _, all_preds, _ = express_mongo_predicates
        vuln_preds = [p for p in all_preds if str(p).startswith('vuln(')]
        assert len(vuln_preds) <= 20, \
            f"Too many CVE predicates: {len(vuln_preds)} (max 20)"

    def test_total_predicate_count_reasonable(self, express_mongo_predicates):
        _, all_preds, goals = express_mongo_predicates
        total = len(all_preds) + len(goals)
        assert total < 80, f"Total predicates {total} > 80 (too bloated)"
        assert total > 15, f"Total predicates {total} < 15 (too sparse)"


def _head_functor(head: str) -> str:
    m = re.match(r'(\w+)\s*\(', head)
    return m.group(1) if m else head


def reachable_functors(available: set, rules: list) -> set:
    """Functor-level forward chaining: which derived predicates become reachable given the
    available primitive functors. Approximates (ignores argument binding) what MulVAL would
    derive, matching the reachability style used elsewhere in this file."""
    derived = set(available)
    changed = True
    while changed:
        changed = False
        for rule in rules:
            head = _head_functor(rule['head'])
            if head in derived:
                continue
            if set(rule['body_preds']).issubset(derived):
                derived.add(head)
                changed = True
    return derived


class TestReconOverviewAlwaysReachable:
    """A graph must ALWAYS be produced: the recon overview is reachable in every scenario,
    while non-exploitable evidence never reaches compromise/execCode (not misleading)."""

    def test_recon_reachable_with_zero_findings(self, web_rules):
        """Bare reachability (attacker_at + host) still derives recon_complete -> non-empty graph."""
        derived = reachable_functors({'attacker_at', 'host'}, web_rules)
        assert 'recon_complete' in derived
        assert 'compromise' not in derived and 'execCode' not in derived

    def test_recon_reachable_from_web_service_only(self, web_rules):
        """An exposed web service still yields the surface overview.

        Only the positive reachability is asserted here: functor-level chaining ignores
        argument binding, so it cannot soundly prove compromise is *un*reachable once
        web_service is present (the git_exposure info-disclosure rule looks satisfiable at the
        functor level though it needs a detected_vuln(info_disclosure) binding). The
        'not misleading' guarantee is asserted by the weakness/zero-finding cases, where no
        web_service is present and the functor-level negative is sound."""
        available = {'attacker_at', 'host', 'connects', 'service', 'exposed', 'web_service'}
        derived = reachable_functors(available, web_rules)
        assert 'recon_complete' in derived

    def test_generic_weakness_is_recon_only_not_compromise(self, web_rules):
        """A non-taint weakness annotates the recon overview but NEVER chains to compromise."""
        available = {'attacker_at', 'host', 'connects', 'detected_weakness'}
        derived = reachable_functors(available, web_rules)
        assert 'recon_complete' in derived
        assert 'compromise' not in derived and 'execCode' not in derived

    def test_taint_flow_reaches_compromise_and_recon(self, web_rules):
        """A localized taint flow still drives the full exploit chain, with recon alongside."""
        available = {'attacker_at', 'host', 'connects', 'service', 'exposed',
                     'web_service', 'taint_flow'}
        derived = reachable_functors(available, web_rules)
        assert 'compromise' in derived
        assert 'recon_complete' in derived

    def test_recon_goal_is_queried(self):
        """generate_attack_goals must query recon_complete so the overview isn't pruned."""
        agg = PredicateAggregator(host='target')
        goals = ' '.join(agg.generate_attack_goals())
        assert 'attackGoal(recon_complete(' in goals


class TestGradedHeuristicTier:
    """Tier-2 sink_evidence must confirm (and reach compromise) ONLY when the app also exposes
    user input — it stays localized and gated, never a free-standing generic path."""

    # web_service is deliberately omitted so this isolates the tier-2 gate: with web_service
    # present, the pre-existing git_exposure info-disclosure rule looks satisfiable at the
    # functor level (argument binding is ignored) and would reach compromise regardless of
    # sink_evidence — the same unsound-negative caveat noted on test_recon_reachable_from_web_service_only.
    def test_sink_evidence_with_user_input_reaches_compromise(self, web_rules):
        available = {'attacker_at', 'host', 'connects', 'service', 'exposed',
                     'sink_evidence', 'has_user_input'}
        derived = reachable_functors(available, web_rules)
        assert 'compromise' in derived
        assert 'recon_complete' in derived

    def test_sink_evidence_without_user_input_does_not_confirm(self, web_rules):
        """Without has_user_input the heuristic sink cannot confirm, so no compromise/execCode —
        the sink alone must not fabricate an exploit path."""
        available = {'attacker_at', 'host', 'connects', 'service', 'exposed',
                     'sink_evidence'}
        derived = reachable_functors(available, web_rules)
        assert 'recon_complete' in derived
        assert 'compromise' not in derived and 'execCode' not in derived

    def test_prototype_pollution_chain_present(self, web_rules):
        heads = {_head_functor(r['head']) for r in web_rules}
        assert 'prototype_pollution_surface' in heads
        assert 'prototype_pollution_confirmed' in heads
        # A confirmed prototype pollution must be able to reach the compromise objective.
        assert any('prototype_pollution_confirmed' in r['body_raw']
                   and r['head'].startswith('compromise') for r in web_rules)


if __name__ == '__main__':
    pytest.exit(pytest.main([__file__, '-v']))
