#!/usr/bin/env python3
"""Semgrep parser strategy.

Consumes findings from the custom taint rules in semgrep_rules/ (PHP, JS/TS, Python, Java;
and, as a fallback, stock owasp-top-ten findings) and emits *localized* dataflow predicates
that drive the confirmation stage of kb/web_security_rules.P:

    taint_flow(Host, Port, Param, File, Line, Class, Sink)   -- a proven source->sink dataflow
    sink_evidence(Host, Port, Param, File, Line, Class, Sink)-- tier-2: a dangerous sink shape with
                                                                a dynamic argument, no proven dataflow
    flag_location(Host, Where, Ref, File, Line)              -- where the flag lives
    access_gate(Host, File, Line, Gate)                      -- precondition on a flag endpoint

Each predicate carries the file:line so the generated attack graph differs per challenge and
points the agent at the actual bug instead of a generic vuln-class checklist.
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from base_parser import Predicate, ScannerStrategy

# Stock-rule metadata vulnerability_class -> our class vocabulary (fallback path).
_METADATA_CLASS_MAP = {
    'cross-site-scripting (xss)': 'xss',
    'cross site scripting (xss)': 'xss',
    'cross-site scripting': 'xss',
    'sql injection': 'sqli',
    'nosql injection': 'nosql_injection',
    'command injection': 'cmdi',
    'server-side request forgery (ssrf)': 'ssrf',
    'server-side request forgery': 'ssrf',
    'path traversal': 'path_traversal',
    'directory traversal': 'path_traversal',
    'insecure deserialization': 'deserialization',
    'xml external entity': 'xxe',
    'server-side template injection': 'ssti',
}

# Known dangerous sink callees, most-specific (dotted) first so we report the tightest match.
_SINK_FUNCS = (
    # JS / Node
    'child_process.execSync', 'child_process.spawn', 'child_process.exec',
    'fs.createReadStream', 'fs.readFileSync', 'fs.readFile', 'res.sendFile', 'res.render',
    'axios.get', 'axios.post', 'https.get', 'http.get',
    'execSync', 'fetch', 'got',
    # Python
    'subprocess.check_output', 'subprocess.Popen', 'subprocess.call', 'subprocess.run',
    'os.system', 'os.popen', 'urllib.request.urlopen',
    'requests.request', 'requests.post', 'requests.get',
    'render_template_string', 'send_from_directory', 'send_file', 'executescript',
    'urlopen', 'execute',
    # Java
    'Runtime.getRuntime().exec', 'ProcessBuilder', 'FileInputStream', 'FileReader',
    'Files.readAllBytes', 'executeQuery', 'executeUpdate', 'parseExpression',
    # PHP (original)
    'shell_exec', 'proc_open', 'passthru', 'file_get_contents', 'include_once',
    'require_once', 'curl_exec', 'readfile', 'system', 'popen', 'exec', 'eval',
    'include', 'require', 'header', 'fopen', 'setcookie',
)

# Source-parameter extractors across languages; first single-param hit names the taint source.
# The request/req *container* attribute (args/form/query/GET/POST/json/cookies/headers/...) is
# left as \w+ rather than enumerated, so a new framework whose request object exposes params
# under a different container name (e.g. a future req.cookies.x or ctx.query.x) is picked up
# without adding a new regex - only the *shape* of the access (attribute / [..] / .get(..)) needs
# covering per language, not each framework's container vocabulary.
_PARAM_RES = (
    # PHP superglobals: $_GET['x'] (fixed set - PHP has no equivalent container-name variety)
    re.compile(r"""\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['"]([^'"]+)['"]\s*\]"""),
    # JS/Node (Express/Koa/...): req.<container>.x / req.<container>['x']. \b anchors the
    # capture to the full identifier (it never matches mid-word), so the trailing negative
    # lookahead can't be defeated by backtracking into a method name like ".get(" -> "ge".
    re.compile(r"""req\.\w+\.([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()"""),
    re.compile(r"""req\.\w+\[\s*['"]([^'"]+)['"]\s*\]"""),
    # Python (Flask/Django/FastAPI/...): request.<container>.get('x') / request.<container>['x']
    re.compile(r"""request\.\w+\.get\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""request\.\w+\[\s*['"]([^'"]+)['"]\s*\]"""),
    # Python (Bottle/...): request.<container>.x (attribute access, e.g. FormsDict). \b plus
    # the negative lookahead skips method calls like the .get(...) case above, without being
    # defeated by backtracking into the method name (e.g. "get(" -> "ge").
    re.compile(r"""request\.\w+\.([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()"""),
    # Java servlet: request.getParameter("x") / request.getHeader("x") - already generic since
    # the literal argument, not a container name, is the param.
    re.compile(r"""\.(?:getParameter|getHeader)\(\s*['"]([^'"]+)['"]\s*\)"""),
)


def infer_web_port(start_dir: Path) -> int:
    """Infer the published web port from a docker-compose.yml near the target. Default 80."""
    cur = start_dir
    for _ in range(5):
        if not cur or not cur.exists():
            break
        for name in ('docker-compose.yml', 'docker-compose.yaml'):
            compose = cur / name
            if compose.exists():
                port = _published_port_from_compose(compose.read_text(errors='replace'))
                if port:
                    return port
        # also look one level down in a conventional env/ dir
        for sub in ('env', '.'):
            for name in ('docker-compose.yml', 'docker-compose.yaml'):
                compose = cur / sub / name
                if compose.exists():
                    port = _published_port_from_compose(compose.read_text(errors='replace'))
                    if port:
                        return port
        cur = cur.parent
    return 80


def _published_port_from_compose(text: str) -> Optional[int]:
    # Match "8099:80", '8099:80', or 127.0.0.1:17747:80 in a ports: list.
    for m in re.finditer(r"-\s*['\"]?([\d.]+:)?(\d+):(\d+)['\"]?", text):
        external = m.group(2)
        try:
            return int(external)
        except ValueError:
            continue
    return None


class SemgrepParserStrategy(ScannerStrategy):
    """Parse Semgrep JSON output into localized dataflow / flag-location predicates."""

    def __init__(self, host: str = 'localhost', target_dir: Optional[str] = None):
        super().__init__(host=host)
        self.target_dir = Path(target_dir) if target_dir else None
        # Set by PredicateAggregator.parse_all() from nmap's discovered web port, so
        # taint_flow lands on the same port as connects/web_service and localized
        # confirmation can actually join into initial_access. Takes priority over the
        # compose-based guess below, which is a fallback for nmap-less runs.
        self.web_port_hint: Optional[int] = None
        self._source_cache: Dict[str, Optional[str]] = {}

    def get_scanner_name(self) -> str:
        return 'Semgrep'

    def parse(self, input_file: str) -> List[Predicate]:
        self.clear()
        self._source_cache = {}

        try:
            with open(input_file, 'r', encoding='utf-8') as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError) as error:
            print(f"[!] Warning: Failed to parse Semgrep file {input_file}: {error}", file=sys.stderr)
            return []

        results = data.get('results', [])
        host_s = self.sanitize(self.host)
        port = self._infer_port(results)

        seen: Set[Tuple[str, ...]] = set()
        n_flow = n_flag = n_gate = n_weak = n_sink = 0

        for finding in results:
            finding_path = str(finding.get('path', '')).replace('\\', '/')
            if self._is_solution_or_metadata(finding_path):
                # Exploit/solution code and challenge metadata aren't the deployed app; a
                # "vuln" found there would be a misleading, unexploitable path.
                continue
            file_name = Path(finding_path or 'unknown').name
            line = int(finding.get('start', {}).get('line', 0) or 0)
            cls = self._classify(finding)
            if cls == 'flag_source_code':
                # Flag-in-source is intentionally not a standalone path (it needs a proven exec
                # chain, see kb/web_security_rules.P); skip rather than emit a direct compromise.
                continue
            if not cls:
                # A real Semgrep hit that isn't a taint class — a hygiene/config weakness
                # (runs-as-root, weak cookie flags, ...). Surface it as a localized recon
                # annotation instead of dropping it: orients the agent at a concrete file:line
                # without fabricating an exploit path.
                category = self._weakness_category(finding)
                key = ('weak', file_name, str(line), category)
                if key not in seen:
                    seen.add(key)
                    self.add_predicate(
                        f"detected_weakness({host_s}, {port}, {self.atom(category)}, "
                        f"{self.sanitize(file_name)}, {line}).",
                        'detected_weakness',
                    )
                    n_weak += 1
                continue

            if cls == 'flag_cookie':
                key = ('flag', 'cookie')
                if key not in seen:
                    seen.add(key)
                    self.add_predicate(
                        f"flag_location({host_s}, cookie, 'flag', {self.sanitize(file_name)}, {line}).",
                        'flag_location',
                    )
                    n_flag += 1
                continue

            if cls == 'gate_localhost_only':
                key = ('gate', file_name, str(line))
                if key not in seen:
                    seen.add(key)
                    self.add_predicate(
                        f"access_gate({host_s}, {self.sanitize(file_name)}, {line}, localhost_only).",
                        'access_gate',
                    )
                    n_gate += 1
                continue

            # Tier-2 heuristic evidence: a dangerous sink shape (dynamically-built argument)
            # matched WITHOUT a proven source->sink dataflow (fires across function boundaries the
            # free Semgrep engine can't taint-track). Emit ONLY sink_evidence so it can't borrow
            # tier-1 confidence: the web KB confirms it at low confidence, gated on has_user_input.
            if self._is_heuristic(finding):
                param = self._source_param(finding)
                sink = self._sink_func(finding, cls)
                key = ('sink', file_name, str(line), cls)
                if key not in seen:
                    seen.add(key)
                    self.add_predicate(
                        f"sink_evidence({host_s}, {port}, {self.sanitize(param)}, "
                        f"{self.sanitize(file_name)}, {line}, {self.atom(cls)}, {self.sanitize(sink)}).",
                        'sink_evidence',
                        {'check_id': finding.get('check_id', ''), 'cwe': self._cwe(finding)},
                    )
                    n_sink += 1
                continue

            # otherwise: a tainted source -> sink dataflow
            param = self._source_param(finding)
            sink = self._sink_func(finding, cls)
            key = ('flow', file_name, str(line), cls)
            if key not in seen:
                seen.add(key)
                self.add_predicate(
                    f"taint_flow({host_s}, {port}, {self.sanitize(param)}, "
                    f"{self.sanitize(file_name)}, {line}, {self.atom(cls)}, {self.sanitize(sink)}).",
                    'taint_flow',
                    {'check_id': finding.get('check_id', ''), 'cwe': self._cwe(finding)},
                )
                # Non-localized evidence twin: lets the web KB's detected_vuln-based
                # confirmation fire for classes whose taint atom differs from a web class.
                self.add_predicate(
                    f"detected_vuln({host_s}, {port}, {self.atom(cls)}).",
                    'semgrep_vuln_evidence',
                )
                n_flow += 1

        print(
            f"[Semgrep] {n_flow} taint flows, {n_sink} heuristic sinks, {n_flag} flag locations, "
            f"{n_gate} access gates, {n_weak} weaknesses"
        )
        return self.predicates

    @staticmethod
    def _is_heuristic(finding: Dict[str, Any]) -> bool:
        meta = (finding.get('extra', {}) or {}).get('metadata', {}) or {}
        return str(meta.get('evidence_tier', '')).lower() == 'heuristic'

    @staticmethod
    def _is_solution_or_metadata(path: str) -> bool:
        # Exclude exploit/solution code everywhere, and the non-deployed parts of metadata/
        # (metadata/solution, metadata/requirements.sh, metadata/metadata.json). Do NOT
        # blanket-exclude metadata/ itself: some challenges (e.g. sekai frog-waf) build the
        # deployed app from metadata/challenge/, which must stay scannable.
        parts = Path(path).parts
        for i, part in enumerate(parts):
            if part == 'solution' or part.startswith('solution'):
                return True
            if part == 'metadata' and i + 1 < len(parts) and parts[i + 1] in (
                'solution', 'requirements.sh', 'metadata.json',
            ):
                return True
        return False

    # -- classification --

    def _classify(self, finding: Dict[str, Any]) -> Optional[str]:
        meta = (finding.get('extra', {}) or {}).get('metadata', {}) or {}
        # custom rules set a single vuln_class
        direct = meta.get('vuln_class')
        if isinstance(direct, str) and direct:
            return direct
        # fallback: stock owasp rules expose vulnerability_class as a list
        for value in meta.get('vulnerability_class', []) or []:
            mapped = _METADATA_CLASS_MAP.get(re.sub(r'\s+', ' ', str(value).lower()).strip())
            if mapped:
                return mapped
        return None

    # -- helpers --

    def _infer_port(self, results: List[Dict[str, Any]]) -> int:
        if self.web_port_hint:
            return self.web_port_hint
        if self.target_dir:
            return infer_web_port(self.target_dir)
        for finding in results:
            p = finding.get('path')
            if p and Path(p).exists():
                return infer_web_port(Path(p).parent)
        return 80

    def _read_source(self, finding: Dict[str, Any]) -> Optional[str]:
        raw = str(finding.get('path', ''))
        if raw in self._source_cache:
            return self._source_cache[raw]
        candidates = []
        if raw:
            candidates.append(Path(raw))
            if self.target_dir:
                candidates.append(self.target_dir / Path(raw).name)
        text: Optional[str] = None
        for c in candidates:
            try:
                if c.exists():
                    text = c.read_text(encoding='utf-8', errors='replace')
                    break
            except OSError:
                continue
        self._source_cache[raw] = text
        return text

    @staticmethod
    def _find_params(text: str) -> List[str]:
        """Ordered-unique request parameters named anywhere in the given source text."""
        params: List[str] = []
        for regex in _PARAM_RES:
            for name in regex.findall(text):
                if name not in params:
                    params.append(name)
        return params

    def _source_param(self, finding: Dict[str, Any]) -> str:
        # Prefer a param named on the matched line; else the file's single request param.
        lines = str((finding.get('extra', {}) or {}).get('lines', ''))
        on_line = self._find_params(lines)
        if len(on_line) == 1:
            return on_line[0]
        text = self._read_source(finding)
        if text:
            params = self._find_params(text)
            if len(params) == 1:
                return params[0]
        return 'user_input'

    def _sink_func(self, finding: Dict[str, Any], cls: str) -> str:
        lines = str((finding.get('extra', {}) or {}).get('lines', ''))
        for fn in _SINK_FUNCS:
            if re.search(r'\b' + re.escape(fn) + r'\s*\(', lines):
                return fn
        return cls + '_sink'

    def _cwe(self, finding: Dict[str, Any]) -> str:
        meta = (finding.get('extra', {}) or {}).get('metadata', {}) or {}
        cwe = meta.get('cwe')
        if isinstance(cwe, list):
            return cwe[0] if cwe else ''
        return str(cwe or '')

    def _weakness_category(self, finding: Dict[str, Any]) -> str:
        """Short atom describing a non-taint finding, for the recon weakness annotation.

        Prefer the OWASP vulnerability_class, then the CWE number, then the rule id — whichever
        is available — so the graph leaf names what was found (e.g. improper_authorization).
        """
        meta = (finding.get('extra', {}) or {}).get('metadata', {}) or {}
        for value in meta.get('vulnerability_class', []) or []:
            text = re.sub(r'[^a-z0-9]+', '_', str(value).lower()).strip('_')
            if text:
                return text
        match = re.search(r'CWE-(\d+)', self._cwe(finding))
        if match:
            return f"cwe_{match.group(1)}"
        check = str(finding.get('check_id', '') or '').rsplit('.', 1)[-1]
        return check or 'weakness'
