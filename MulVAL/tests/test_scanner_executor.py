#!/usr/bin/env python3
"""Focused tests for external scanner command construction."""

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock


sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner_executor import ScannerExecutor


def test_trivy_allows_database_initialization(tmp_path, monkeypatch):
    target = tmp_path / 'target'
    output_dir = tmp_path / 'output'
    output_file = output_dir / 'scan_results' / 'trivy_results.json'
    target.mkdir()
    output_file.parent.mkdir(parents=True)
    run = Mock(return_value=subprocess.CompletedProcess([], 0, '', ''))
    monkeypatch.setattr(subprocess, 'run', run)
    scanner_outputs = {}

    executor = ScannerExecutor(target=target, output_dir=output_dir, host='127.0.0.1')

    assert executor._run_trivy(output_file, scanner_outputs)
    command = run.call_args.args[0]
    assert command[:2] == ['trivy', 'fs']
    assert '--skip-db-update' not in command
    assert '--skip-java-db-update' not in command
    assert scanner_outputs == {'trivy': str(output_file)}


def test_semgrep_runs_directly_with_absolute_paths(tmp_path, monkeypatch):
    target = tmp_path / 'target'
    output_dir = tmp_path / 'output'
    output_file = output_dir / 'scan_results' / 'semgrep_results.json'
    target.mkdir()
    output_file.parent.mkdir(parents=True)
    payload = {'version': '1.168.0', 'results': [], 'errors': []}
    run = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), ''))
    monkeypatch.setattr(subprocess, 'run', run)
    scanner_outputs = {}

    executor = ScannerExecutor(target=target, output_dir=output_dir, host='127.0.0.1')

    assert executor._run_semgrep(output_file, scanner_outputs)
    command = run.call_args.args[0]
    assert command[:2] == ['semgrep', 'scan']
    assert 'docker' not in command
    assert str(target.resolve()) == command[-1]
    assert Path(command[command.index('--config') + 1]).is_absolute()
    assert scanner_outputs == {'semgrep': str(output_file)}
    assert json.loads(output_file.read_text(encoding='utf-8')) == payload


def test_semgrep_rejects_nonzero_exit_with_json_output(tmp_path, monkeypatch):
    target = tmp_path / 'target'
    output_file = tmp_path / 'output' / 'scan_results' / 'semgrep_results.json'
    target.mkdir()
    output_file.parent.mkdir(parents=True)
    run = Mock(return_value=subprocess.CompletedProcess([], 7, '{"results": []}', 'invalid configuration'))
    monkeypatch.setattr(subprocess, 'run', run)
    scanner_outputs = {}

    executor = ScannerExecutor(target=target, output_dir=tmp_path / 'output', host='127.0.0.1')

    assert not executor._run_semgrep(output_file, scanner_outputs)
    assert scanner_outputs == {}
    assert not output_file.exists()
