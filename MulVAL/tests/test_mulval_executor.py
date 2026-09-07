#!/usr/bin/env python3
"""Focused tests for local MulVAL graph rendering."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock


sys.path.insert(0, str(Path(__file__).parent.parent))

from mulval_executor import MulvalExecutor


def _executor(tmp_path):
    output_dir = tmp_path / 'output'
    output_dir.mkdir()
    return MulvalExecutor(
        base_dir=tmp_path,
        output_dir=output_dir,
        host='127.0.0.1',
        trace_processor=Mock(),
    )


def test_run_prefers_local_mulval(tmp_path, monkeypatch):
    rules = tmp_path / 'rules.P'
    predicates = tmp_path / 'input.P'
    rules.write_text('rule.', encoding='utf-8')
    predicates.write_text('fact.', encoding='utf-8')
    executor = _executor(tmp_path)
    local = Mock(return_value=True)
    docker = Mock(return_value=True)
    monkeypatch.setattr(executor, '_run_mulval_local', local)
    monkeypatch.setattr(executor, '_run_mulval_docker', docker)

    assert executor.run(predicates, rules)
    local.assert_called_once()
    docker.assert_not_called()


def test_local_mulval_rejects_missing_trace(tmp_path, monkeypatch):
    predicates = tmp_path / 'input.P'
    rules = tmp_path / 'rules.P'
    predicates.write_text('fact.', encoding='utf-8')
    rules.write_text('rule.', encoding='utf-8')
    executor = _executor(tmp_path)
    run = Mock(return_value=subprocess.CompletedProcess([], 0, '', ''))
    monkeypatch.setattr(subprocess, 'run', run)

    assert not executor._run_mulval_local(predicates, rules)


def test_local_renderer_writes_graph_inputs_and_pdf(tmp_path, monkeypatch):
    output_dir = tmp_path / 'output'
    output_dir.mkdir()
    attack_graph_trace = tmp_path / 'trace_output_attackgraph.P'
    attack_graph_trace.write_text('trace.', encoding='utf-8')
    graph_text = '\n'.join([
        '1,"recon_complete(host)","OR",0',
        '2,"host(host)","LEAF",1',
        '1,2,-1',
    ]) + '\n'

    def run(command, **kwargs):
        if command[0] == 'attack_graph':
            return subprocess.CompletedProcess(command, 0, graph_text, '')
        if command[0] == 'render.sh':
            (output_dir / 'AttackGraph.pdf').write_bytes(b'%PDF-smoke')
            return subprocess.CompletedProcess(command, 0, '', '')
        raise AssertionError(f'Unexpected command: {command}')

    monkeypatch.setattr(subprocess, 'run', run)
    executor = MulvalExecutor(base_dir=tmp_path, output_dir=output_dir, host='127.0.0.1', trace_processor=Mock())

    assert executor._generate_attack_graph_local(attack_graph_trace)
    assert (output_dir / 'AttackGraph.txt').read_text(encoding='utf-8') == graph_text
    assert (output_dir / 'VERTICES.CSV').read_text(encoding='utf-8').splitlines() == [
        '1,"recon_complete(host)","OR",0',
        '2,"host(host)","LEAF",1',
    ]
    assert (output_dir / 'ARCS.CSV').read_text(encoding='utf-8') == '1,2,-1\n'
    assert (output_dir / 'AttackGraph.pdf').stat().st_size > 0
