#!/usr/bin/env python3
"""Tests for TraceProcessor path emission — specifically that alternative routes to the same
terminal fact each surface (no single-justification displacement) and rank by confidence."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from trace_processor import TraceProcessor


# A terminal fact compromise(h,user) derivable by TWO routes:
#   - an XSS credential route (cred_obtained via xss session hijack), and
#   - a tier-2 heuristic path-traversal route (cred_obtained via a sink_evidence file read).
# Both reach compromise(h,user) through rule "Credential access ..." at equal confidence, so the
# old single-justification emission dropped one of them. Both must now surface.
_TRACE = """
because(1,rule_desc('Evidence-backed XSS session hijacking from static findings',0.82),initial_access(h,xss_session,web_user),[detected_vuln(h,80,xss)]).
because(2,rule_desc('XSS steals session cookies that grant authenticated access',0.74),cred_obtained(h,session_token,h),[initial_access(h,xss_session,web_user)]).
because(3,rule_desc('Heuristic path traversal dynamically-built path at a file sink',0.5),path_traversal_confirmed(h,80),[sink_evidence(h,80,p,notes.py,1,path_traversal,s)]).
because(4,rule_desc('Path traversal reads credential files',0.65),cred_obtained(h,file_credentials,h),[path_traversal_confirmed(h,80)]).
because(5,rule_desc('Credential access constitutes partial compromise',0.7),compromise(h,user),[cred_obtained(h,session_token,h)]).
because(6,rule_desc('Credential access constitutes partial compromise',0.7),compromise(h,user),[cred_obtained(h,file_credentials,h)]).
"""


@pytest.fixture
def paths(tmp_path):
    trace = tmp_path / "trace_output.P"
    trace.write_text(_TRACE.strip() + "\n")
    out = tmp_path / "paths.json"
    TraceProcessor().parse_trace_to_json(trace_file=trace, paths_file=out, host='h')
    return json.loads(out.read_text())


class TestAlternativeRoutesSurface:
    def test_both_routes_emitted_for_shared_terminal(self, paths):
        text = json.dumps(paths).lower()
        # Both the required-vuln route (xss) and the heuristic route (path traversal) surface.
        assert 'xss' in text
        assert 'path traversal' in text

    def test_distinct_routes_are_separate_paths(self, paths):
        compromise_paths = [p for p in paths['paths']
                            if p['goal'] == 'compromise(h,user)']
        # One path per distinct route to the same terminal (deduped by technique-set).
        assert len(compromise_paths) == 2

    def test_higher_confidence_route_ranks_first(self, paths):
        compromise_paths = [p for p in paths['paths']
                            if p['goal'] == 'compromise(h,user)']
        # The XSS route (min_confidence 0.7 over 0.74/0.82/0.7) ranks above the heuristic
        # path-traversal route (min_confidence 0.5).
        assert compromise_paths[0]['min_confidence'] > compromise_paths[1]['min_confidence']
        assert 'xss' in json.dumps(compromise_paths[0]).lower()
