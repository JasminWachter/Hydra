#!/usr/bin/env python3
"""Nmap parser strategy."""

import sys
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Set

from base_parser import (
    AUTH_SERVICES,
    DATABASE_SERVICES,
    WEB_PORTS,
    WEB_SERVICES,
    Predicate,
    ScannerStrategy,
)


class NmapParserStrategy(ScannerStrategy):
    """Parse Nmap XML output for services and topology predicates."""

    def __init__(self, host: str = 'localhost'):
        super().__init__(host=host)
        self.services: List[Dict[str, Any]] = []
        self.web_ports: Set[int] = set()

    def get_scanner_name(self) -> str:
        return "Nmap"

    def _host_id(self, ip: str) -> str:
        if self.host and self.host != 'localhost':
            return self.host
        return 'host_' + ip.replace('.', '_')

    def parse(self, input_file: str) -> List[Predicate]:
        self.clear()
        self.services = []
        self.web_ports = set()

        try:
            tree = ET.parse(input_file)
            root = tree.getroot()
        except (FileNotFoundError, ET.ParseError) as error:
            print(f"[!] Warning: Failed to parse Nmap file {input_file}: {error}", file=sys.stderr)
            return []

        hosts_count = 0
        services_count = 0

        for host_elem in root.findall('.//host'):
            addr_elem = host_elem.find('.//address[@addrtype="ipv4"]')
            if addr_elem is None:
                addr_elem = host_elem.find('.//address[@addrtype="ipv6"]')
            if addr_elem is None:
                continue

            host_ip = addr_elem.get('addr', 'unknown')
            host_id = self._host_id(host_ip)
            host_s = self.sanitize(host_id)
            hosts_count += 1

            self.add_predicate(f"host({host_s}).", 'network_topology')

            # No OS detection: the scan command doesn't run -O (needs raw sockets/root, not
            # reliably available), so <osmatch> is never present in the XML this parses.

            roles: Set[str] = set()
            for port_elem in host_elem.findall('.//port'):
                state = port_elem.find('state')
                if state is not None and state.get('state') != 'open':
                    continue

                port_id = port_elem.get('portid', '0')
                protocol = port_elem.get('protocol', 'tcp')

                service_elem = port_elem.find('service')
                if service_elem is None:
                    continue

                svc_name = service_elem.get('name', 'unknown')
                svc_product = service_elem.get('product', svc_name)
                svc_version = service_elem.get('version', '')

                self.add_predicate(
                    f"service({host_s}, {port_id}, {protocol}, "
                    f"{self.sanitize(svc_name)}, {self.sanitize(svc_version)}).",
                    'services',
                    {
                        'host': host_id,
                        'port': port_id,
                        'service': svc_name,
                        'product': svc_product,
                        'version': svc_version,
                    },
                )
                services_count += 1

                self.add_predicate(f"connects('internet', {host_s}, {port_id}).", 'network_topology')
                self.add_predicate(f"exposed({host_s}, {port_id}).", 'network_topology')

                svc_info = {
                    'host': host_id,
                    'port': int(port_id),
                    'service': svc_name,
                    'product': svc_product,
                    'version': svc_version,
                }
                self.services.append(svc_info)

                if svc_name in WEB_SERVICES or int(port_id) in WEB_PORTS:
                    roles.add('webserver')
                    self.web_ports.add(int(port_id))
                if svc_name in DATABASE_SERVICES:
                    roles.add('database')
                if svc_name in AUTH_SERVICES:
                    roles.add('ssh_server' if 'ssh' in svc_name else 'auth_service')

                for script in port_elem.findall('.//script'):
                    script_id = script.get('id', '')
                    script_output = script.get('output', '')
                    self._parse_nmap_script(host_s, int(port_id), script_id, script_output)

            for role in sorted(roles):
                self.add_predicate(f"role({host_s}, {self.sanitize(role)}).", 'roles')

            if 'database' in roles:
                self.add_predicate(f"has_data({host_s}, 'customer_records').", 'data_context')
                self.add_predicate(f"has_data({host_s}, 'sensitive').", 'data_context')

        print(f"[Nmap] Parsed {hosts_count} hosts, {services_count} services")
        return self.predicates

    def _parse_nmap_script(self, host_s: str, port: int, script_id: str, output: str) -> None:
        output_lower = output.lower()

        if script_id == 'http-methods' and ('PUT' in output or 'DELETE' in output):
            self.add_predicate(f"dangerous_http_methods({host_s}, {port}).", 'web_context')

        if script_id in ('http-title', 'http-server-header'):
            for framework in [
                'express', 'nginx', 'apache', 'django', 'flask',
                'fastapi', 'uvicorn', 'gunicorn', 'tomcat', 'iis', 'php',
            ]:
                if framework in output_lower:
                    self.add_predicate(
                        f"web_framework({host_s}, {port}, {self.sanitize(framework)}).",
                        'web_context',
                    )

            if any(token in output_lower for token in ['api', 'webhook', 'gunicorn', 'uvicorn', 'fastapi']):
                self.add_predicate(
                    f"has_api_endpoint({host_s}, {port}, 'POST', '/api').",
                    'web_context',
                )

        if script_id in ('http-default-accounts', 'ssh-auth-methods') and 'password' in output_lower:
            self.add_predicate(
                f"auth_possible({host_s}, 'default', 'password').",
                'auth_context',
            )

        if script_id == 'mongodb-info' and ('authentication' not in output_lower or 'disabled' in output_lower):
            self.add_predicate(f"no_auth_required({host_s}, {port}).", 'auth_context')
