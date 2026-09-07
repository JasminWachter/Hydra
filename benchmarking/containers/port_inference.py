#!/usr/bin/env python3
"""Port inference heuristics for Dockerfile-only challenge tasks."""

import re
from pathlib import Path
from typing import List


class PortInferrer:
    """Infers the port a challenge service listens on from static analysis."""

    _PLAUSIBLE_PORTS = {80, 443, 1234, 1337, 3000, 4000, 5000, 8000, 8080, 8888}

    _SOURCE_PATTERNS = [
        r'\.listen\(\s*(?:\w+\s*\|\|\s*)?(\d{2,5})',   # JS app.listen(PORT || 1234)
        r'(?:PORT|port)\s*\|\|\s*(\d{2,5})',            # JS/TS: process.env.PORT || 8080
        r'run\s*\(.*?port\s*=\s*(\d{2,5})',             # Python bottle/flask run(port=8080)
        r'port\s*=\s*(\d{2,5})',                         # Python port=8080
        r'"0\.0\.0\.0:(\d{2,5})"',                      # Go/generic "0.0.0.0:PORT"
        r'unwrap_or[^"]*"(\d{2,5})"',                   # Rust unwrap_or_else(|_| "1337")
    ]

    _SOURCE_EXTENSIONS = ['*.py', '*.js', '*.ts', '*.rb', '*.go', '*.rs', '*.php']

    _SKIP_DIRS = {'node_modules', 'vendor', '.git', '__pycache__', 'target', 'dist'}

    @staticmethod
    def from_dockerfile(dockerfile: Path) -> List[str]:
        """Extract port numbers from a Dockerfile using EXPOSE, ENV, CMD/ENTRYPOINT heuristics."""
        ports: List[str] = []
        try:
            content = dockerfile.read_text(errors='replace')
            for line in content.splitlines():
                stripped = line.strip()
                upper = stripped.upper()

                if upper.startswith('EXPOSE'):
                    for token in stripped.split()[1:]:
                        port_str = token.split('/')[0]
                        if port_str.isdigit():
                            ports.append(port_str)

                if upper.startswith('ENV') and 'PORT' in upper:
                    m = re.search(r'PORT[=\s]+(\d{2,5})', stripped, re.IGNORECASE)
                    if m:
                        ports.append(m.group(1))

                if upper.startswith(('ENTRYPOINT', 'CMD')):
                    m = re.search(r'-p["\s,]+(\d{2,5})', stripped)
                    if m:
                        ports.append(m.group(1))

                if upper.startswith('FROM') and any(
                    kw in upper for kw in ('NGINX', 'APACHE', 'HTTPD', 'BASE_WEB')
                ):
                    ports.append('80')

        except Exception:
            pass
        return ports

    @classmethod
    def from_source(cls, context_dir: Path) -> List[str]:
        """Scan source files for port binding patterns, skipping dependency directories."""
        ports: List[str] = []
        try:
            for ext in cls._SOURCE_EXTENSIONS:
                for src_file in context_dir.rglob(ext):
                    if any(part in cls._SKIP_DIRS for part in src_file.parts):
                        continue
                    try:
                        text = src_file.read_text(errors='replace')
                        for pattern in cls._SOURCE_PATTERNS:
                            for m in re.finditer(pattern, text, re.IGNORECASE):
                                candidate = m.group(1)
                                if int(candidate) in cls._PLAUSIBLE_PORTS:
                                    ports.append(candidate)
                    except Exception:
                        pass
        except Exception:
            pass

        seen: set = set()
        return [p for p in ports if not (p in seen or seen.add(p))]
