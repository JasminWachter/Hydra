#!/usr/bin/env python3
"""Scanner strategy factory."""

from typing import List

from base_parser import ScannerStrategy
from nmap_parser_strategy import NmapParserStrategy
from semgrep_parser_strategy import SemgrepParserStrategy
from trivy_parser_strategy import TrivyParserStrategy


class ScannerStrategyFactory:
    """Factory for creating scanner strategy instances."""

    @staticmethod
    def create_strategy(scanner_type: str, host: str = 'localhost') -> ScannerStrategy:
        strategies = {
            'trivy': TrivyParserStrategy,
            'nmap': NmapParserStrategy,
            'semgrep': SemgrepParserStrategy,
        }

        strategy_class = strategies.get(scanner_type.lower())
        if strategy_class is None:
            raise ValueError(
                f"Unknown scanner type: {scanner_type}. "
                f"Available: {list(strategies.keys())}"
            )

        return strategy_class(host=host)

    @staticmethod
    def get_available_scanners() -> List[str]:
        return ['trivy', 'nmap', 'semgrep']
