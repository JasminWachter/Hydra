#!/usr/bin/env python3
"""Infer web-app features from source files and emit MulVAL predicates."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Iterable, List, Pattern, Set


class AppFeatureExtractor:
    """Config-driven static feature extractor for web vulnerability activation predicates."""

    _IGNORE_DIRS = {
        '.git',
        '.venv',
        'venv',
        'node_modules',
        '__pycache__',
        '.mypy_cache',
        '.pytest_cache',
        'dist',
        'build',
        '.next',
        '.nuxt',
    }

    _TEXT_SUFFIXES = {
        '.js', '.jsx', '.ts', '.tsx', '.py', '.php', '.rb', '.go', '.java', '.kt',
        '.cs', '.json', '.yaml', '.yml', '.toml', '.ini', '.env', '.xml', '.conf',
        '.md', '.txt', '.sh', '.dockerfile',
    }

    _DEFAULT_SIGNALS: Dict[str, object] = {
        'framework_signals': {
            'express': [r'\bexpress\b', r'\bapp\.use\(', r'\brouter\.'],
            'flask': [r'\bflask\b', r'\b@app\.route\('],
            'django': [r'\bdjango\b', r'\burlpatterns\b', r'\bpath\('],
            'fastapi': [r'\bfastapi\b', r'@(?:app|router)\.(?:get|post|put|patch|delete)'],
            'spring': [r'@RestController', r'@Controller', r'@RequestMapping', r'@GetMapping', r'@PostMapping'],
            'rails': [r'\bRails\b', r'config\.routes\.draw', r'resources\s+:'],
            'laravel': [r'\bLaravel\b', r'Route::(?:get|post|put|delete|patch)'],
        },
        'database_signals': {
            'mongodb': [r'\bmongo(?:db|ose)?\b', r'mongodb(?:\+srv)?://'],
            'postgresql': [r'\bpostgres(?:ql)?\b', r'\bpsycopg2\b', r'jdbc:postgresql:'],
            'mysql': [r'\bmysql\b', r'\bmariadb\b', r'jdbc:mysql:'],
            'sqlite': [r'\bsqlite(?:3)?\b'],
            'redis': [r'\bredis\b', r'\bioredis\b', r'redis://'],
        },
        'feature_signals': {
            'user_input': [
                r'request\.(?:args|form|json|values|query|body)',
                r'req\.(?:query|body|params)',
                r'params\[',
                r'query\[',
                r'\binput\(',
                r'\$_(?:GET|POST|REQUEST)',
            ],
            'login': [r'\blogin\b', r'\bsignin\b', r'\bauth(?:enticate)?\b', r'\btoken\b', r'\bjwt\b', r'\bsession\b'],
            'cookie_auth': [r'\bcookie\b', r'set-cookie', r'express-session', r'session\['],
            'file_upload': [r'\bupload\b', r'multipart', r'\bmulter\b', r'request\.files', r'\bIFormFile\b', r'\bFormFile\b'],
            'no_auth': [r'auth\s*=\s*false', r'permitAll\(', r'AllowAnonymous', r'authentication\s+disabled'],
        },
        'api_route_patterns': [
            r'\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)',
            r'@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)',
            r'@(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*["\']?([^"\')\s]+)',
        ],
        'port_patterns': {
            'dockerfile_expose': r'\bEXPOSE\s+(\d{2,5})\b',
            'compose_mapping': r'(?<!\d)(\d{2,5})\s*:\s*(\d{2,5})(?:/\w+)?',
            'env_port': r'\bPORT\s*[=:]\s*["\']?(\d{2,5})',
        },
    }

    def __init__(self, config_path: Path | None = None):
        config = self._load_config(config_path)
        self.framework_patterns = self._compile_named_patterns(config.get('framework_signals', {}))
        self.db_patterns = self._compile_named_patterns(config.get('database_signals', {}))
        self.feature_patterns = self._compile_named_patterns(config.get('feature_signals', {}))
        self.api_route_patterns = self._compile_patterns(config.get('api_route_patterns', []))
        port_cfg = config.get('port_patterns', {})
        self.port_expose_pattern = re.compile(str(port_cfg.get('dockerfile_expose', '')), re.IGNORECASE)
        self.port_mapping_pattern = re.compile(str(port_cfg.get('compose_mapping', '')))
        self.port_env_pattern = re.compile(str(port_cfg.get('env_port', '')), re.IGNORECASE)

    def extract(
        self,
        target_dir: Path,
        host_atom: str,
        candidate_ports: Iterable[int],
    ) -> Dict[str, object]:
        """Extract app-level predicates from source and config files."""
        files = self._candidate_files(target_dir)

        frameworks: Set[str] = set()
        db_types: Set[str] = set()
        routes: Set[tuple[str, str]] = set()
        inferred_ports: Set[int] = {int(p) for p in candidate_ports if int(p) > 0}
        has_user_input = False
        has_login = False
        has_cookie_auth = False
        has_upload = False
        has_no_auth = False

        for path in files:
            text = self._safe_read(path)
            if not text:
                continue

            frameworks.update(self._matched_labels(text, self.framework_patterns))
            db_types.update(self._matched_labels(text, self.db_patterns))

            matched_features = self._matched_labels(text, self.feature_patterns)
            has_user_input = has_user_input or ('user_input' in matched_features)
            has_login = has_login or ('login' in matched_features)
            has_cookie_auth = has_cookie_auth or ('cookie_auth' in matched_features)
            has_upload = has_upload or ('file_upload' in matched_features)
            has_no_auth = has_no_auth or ('no_auth' in matched_features)

            for method, route in self._extract_routes(text):
                routes.add((method, route))

            inferred_ports.update(self._extract_ports(path, text))

        if not inferred_ports and (frameworks or routes):
            inferred_ports = {80}

        predicates: List[str] = []
        for port in sorted(inferred_ports):
            predicates.append(f"connects('internet', {host_atom}, {port}).")
            predicates.append(f"exposed({host_atom}, {port}).")
            predicates.append(f"service({host_atom}, {port}, tcp, 'http', 'inferred').")
            predicates.append(f"web_service({host_atom}, {port}, 'application').")
            if has_user_input or routes:
                predicates.append(f"has_user_input({host_atom}, {port}, 'http_params').")
            if has_login:
                predicates.append(f"has_login_form({host_atom}, {port}).")
            if has_cookie_auth:
                predicates.append(f"has_cookie_auth({host_atom}, {port}).")
            if has_upload:
                predicates.append(f"has_file_upload({host_atom}, {port}).")
            if has_no_auth:
                predicates.append(f"no_auth_required({host_atom}, {port}).")

            for method, route in sorted(routes):
                predicates.append(
                    f"has_api_endpoint({host_atom}, {port}, '{method}', {self._sanitize(route)})."
                )

            for framework in sorted(frameworks):
                predicates.append(f"web_framework({host_atom}, {port}, {self._sanitize(framework)}).")

            for db_type in sorted(db_types):
                predicates.append(f"uses_database({host_atom}, {port}, {self._sanitize(db_type)}).")

        if db_types:
            predicates.append(f"has_data({host_atom}, 'database_records').")

        return {
            'predicates': predicates,
            'web_ports': inferred_ports,
            'stats': {
                'files_scanned': len(files),
                'frameworks': len(frameworks),
                'database_types': len(db_types),
                'routes': len(routes),
            },
        }

    def _load_config(self, config_path: Path | None) -> Dict[str, object]:
        if config_path is None:
            config_path = Path(__file__).resolve().parent / 'config' / 'app_feature_signals.json'

        if not config_path.exists():
            return dict(self._DEFAULT_SIGNALS)

        try:
            loaded = json.loads(config_path.read_text(encoding='utf-8'))
            if isinstance(loaded, dict):
                merged = dict(self._DEFAULT_SIGNALS)
                for key, value in loaded.items():
                    merged[key] = value
                return merged
        except (OSError, json.JSONDecodeError):
            pass
        return dict(self._DEFAULT_SIGNALS)

    def _compile_patterns(self, expressions: object) -> List[Pattern[str]]:
        if not isinstance(expressions, list):
            return []
        compiled: List[Pattern[str]] = []
        for expr in expressions:
            if isinstance(expr, str) and expr:
                compiled.append(re.compile(expr, re.IGNORECASE))
        return compiled

    def _compile_named_patterns(self, mapping: object) -> Dict[str, List[Pattern[str]]]:
        if not isinstance(mapping, dict):
            return {}
        compiled: Dict[str, List[Pattern[str]]] = {}
        for label, expressions in mapping.items():
            if not isinstance(label, str):
                continue
            compiled[label] = self._compile_patterns(expressions)
        return compiled

    def _matched_labels(self, text: str, mapping: Dict[str, List[Pattern[str]]]) -> Set[str]:
        matched: Set[str] = set()
        for label, patterns in mapping.items():
            if any(pattern.search(text) for pattern in patterns):
                matched.add(label)
        return matched

    def _candidate_files(self, target_dir: Path) -> List[Path]:
        if not target_dir.exists() or not target_dir.is_dir():
            return []

        files: List[Path] = []
        for path in target_dir.rglob('*'):
            if len(files) >= 400:
                break
            if not path.is_file():
                continue
            if any(part in self._IGNORE_DIRS for part in path.parts):
                continue

            suffix = path.suffix.lower()
            if suffix in self._TEXT_SUFFIXES or path.name.lower() in {
                'dockerfile', 'package.json', 'docker-compose.yml', 'docker-compose.yaml',
                'requirements.txt', 'pom.xml', 'build.gradle',
            }:
                files.append(path)
        return files

    def _safe_read(self, path: Path) -> str:
        try:
            if path.stat().st_size > 512_000:
                return ''
            return path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            return ''

    def _extract_routes(self, text: str) -> List[tuple[str, str]]:
        routes: List[tuple[str, str]] = []
        for pattern in self.api_route_patterns:
            for match in pattern.findall(text):
                method = str(match[0]).upper()
                route = str(match[1]).strip() or '/'
                if not route.startswith('/'):
                    route = '/' + route
                routes.append((method, route))
        return routes

    def _extract_ports(self, path: Path, text: str) -> Set[int]:
        ports: Set[int] = set()

        if path.name.lower() == 'dockerfile' or path.suffix.lower() == '.dockerfile':
            for match in self.port_expose_pattern.findall(text):
                ports.add(int(match))

        if path.name.lower() in {'docker-compose.yml', 'docker-compose.yaml'}:
            for host_port, container_port in self.port_mapping_pattern.findall(text):
                # Prefer container/app port when available.
                ports.add(int(container_port or host_port))

        for match in self.port_env_pattern.findall(text):
            ports.add(int(match))

        return {p for p in ports if 1 <= p <= 65535}

    @staticmethod
    def _sanitize(text: str) -> str:
        return "'" + text.replace("'", '').replace('\\', '/') + "'"
