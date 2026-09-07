# Interaction Rule Generation

This module contains the rule-generation workflow used to build MulVAL
knowledge bases from ATT&CK-aligned rule artifacts.

## Main Components

- `nlp_pipeline/generate_full_kb.py`: deterministic KB assembler
- `nlp_pipeline/nlp_inputs/`: predicate and variable registries
- `nlp_pipeline/nlp_outputs/`: LLM-generated rule outputs
- `nlp_pipeline/mulval_execution/generate_attack_paths.py`: trace-to-path JSON

## Typical Workflow

1. Generate or refresh rule files under `nlp_outputs/`.
2. Build consolidated KB:

```bash
python3 interaction_rule_generation/nlp_pipeline/generate_full_kb.py
```

3. Use resulting KB in MulVAL runs as needed.

## Runtime Positioning

For day-to-day runtime in this repository, the default ruleset remains:

- `MulVAL/kb/web_security_rules.P`

The generated full interaction KB is mainly for broader ATT&CK coverage and
explicit override scenarios.
