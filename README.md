# HYDRA — HYbrid ReAsoner

Hydra integrates MulVAL attack-path reasoning with the CAI cybersecurity agent
framework. It combines scanner evidence, symbolic attack-graph generation, and
agentic execution without redistributing the upstream CAI source tree.

> [!IMPORTANT]
> **CAI maintenance status:** The upstream CAI repository was archived on
> August 28, 2026 and is no longer actively maintained. Hydra pins CAI 0.5.5 as
> a research dependency; users should not expect upstream bug fixes, security
> patches, compatibility updates, or support.

> [!WARNING]
> **Safety and data handling:** LLM agents can invoke tools and cause unexpected
> or disruptive actions. Run Hydra only in an isolated, disposable environment,
> with least-privilege access, and only against systems you are explicitly
> authorized to test. Depending on configuration, prompts, tool inputs and
> outputs, target information, files, and other context may flow to third-party
> LLM providers, tool services, or telemetry and tracing systems. Do not provide
> sensitive, confidential, personal, or otherwise restricted data. Review the
> policies and data-flow settings of every configured provider and service
> before use; disabling tracing does not prevent data from being sent to the
> selected model provider.

## Architecture

1. Trivy, Semgrep, and Nmap produce security evidence.
2. The pipeline in `MulVAL/` converts that evidence into MulVAL predicates.
3. MulVAL/XSB generates attack paths in `paths.json`.
4. The patched CAI 0.5.5 CLI loads the path index and starts the hybrid reasoner.
5. The agent retrieves full path steps on demand with `get_attack_path(path_id)`.

Hydra-owned runtime code is stored in `MulVAL/`. CAI integration changes are
distributed only as `patches/cai-0.5.5-hydra.patch`.

## CAI dependency and patch

The unmodified Python dependency is pinned in `requirements.txt` as
`cai-framework==0.5.5`:

```bash
python -m pip install -r requirements.txt
```

Native hybrid CLI functionality requires applying the Hydra patch to the exact
CAI 0.5.5 source revision used for development:

```bash
git clone https://github.com/aliasrobotics/cai.git cai-0.5.5
cd cai-0.5.5
git checkout --detach 6d47ccc2d282d6ec42243aa524019adb6bf48127
git apply --check ../hydra/patches/cai-0.5.5-hydra.patch
git apply ../hydra/patches/cai-0.5.5-hydra.patch
python -m pip install -e .
```

The patch SHA-256 and verification results are recorded in
`RELEASE_VERIFICATION.md`. The container build performs the same checkout,
hash verification, patch application, and installation automatically.

## Container environment

Build and start the default development container from the repository root:

```bash
docker compose -f .devcontainer/docker-compose.yml build devenv
docker compose -f .devcontainer/docker-compose.yml up -d devenv
```

GPU access and elevated Docker capabilities are not enabled by default. Put
machine-specific settings in an untracked Compose override.

For local models without external trace export, set both tracing controls:

```bash
export CAI_TRACING=false
export OPENAI_AGENTS_DISABLE_TRACING=true
```

These variables control separate CAI and Agents SDK tracing paths.

The value `sk-1234` appearing in the example environment, container build
verification, and local-model benchmark helper is an intentionally non-secret
placeholder required by OpenAI-compatible clients that reject an empty API key.
Replace it with a real credential only when connecting to a hosted provider.

## Run hybrid reasoning

After installing the patched CAI checkout:

```bash
cai --hybrid-reasoning --hybrid-mode standard --hybrid-target 127.0.0.1
```

Useful options:

- `--hybrid-paths-file <file>` selects a specific `paths.json`.
- `--hybrid-query "<text>"` overrides the default prompt.
- `--hybrid-max-turns <n>` sets the runner turn limit.
- `--hybrid-scan-before-run` runs the scanner pipeline first.
- `--hybrid-mode ctf` selects the CTF-oriented prompt and rules.

## Generate MulVAL paths directly

```bash
python MulVAL/generate_predicates.py \
  --target /path/to/target \
  --output ./graphs \
  --scanners trivy,semgrep,nmap \
  --rules MulVAL/kb/web_security_rules.P
```

The primary output consumed by hybrid reasoning is `graphs/paths.json`.

## Supporting modules

- `interaction_rule_generation/` contains the ATT&CK-to-MulVAL rule-generation
  workflow.
- `benchmarking/` contains attack-graph and agent evaluation tooling.
- `patches/` contains the reviewed CAI integration patch.

## Licensing and provenance

CAI is fetched from its official upstream repository and is not bundled here.
Its original license, MIT notice, citation metadata, and disclaimer are retained
under `licenses/CAI/`. Applying the Hydra patch does not replace or relax CAI's
upstream terms.

MulVAL licensing is preserved in `MulVAL/LICENSE-MULVAL`. The pinned MITRE
ATT&CK dataset source, hashes, copyright notice, and terms are documented in
`licenses/MITRE-ATTACK.md`.
Hydra is not affiliated with or endorsed by Alias Robotics, and this repository
does not publish the `cai-framework` distribution.

## Reproducibility release

The repository state used for the RAISE paper is pinned by the annotated
[`raise-paper-release`](https://github.com/JasminWachter/Hydra/tree/raise-paper-release)
tag. Use that tag, rather than the moving `main` branch, when reproducing the
published setup.

As of September 7, 2026, CAI 0.5.5 remains available from PyPI and the exact
upstream commit used by Hydra remains retrievable from GitHub when fetched
explicitly by SHA. Because CAI's visible Git history was consolidated when the
repository was archived, continued retention of that older Git object is not
guaranteed. The container build therefore requests the exact commit directly.

The non-yanked PyPI 0.5.5 artifacts provide an additional preservation source:

- Wheel SHA-256: `3d5d2b26171d0a4f486c546ab7f3e4192ef1a478a9ac66813cfedf5ee736bfb9`
- Source archive SHA-256: `c8cadb99c69285fb79fb5a9c2f4bf4f36b6c0d6a87564a950a2cc784a2ef1e7c`

The Hydra patch was verified against upstream Git commit
`6d47ccc2d282d6ec42243aa524019adb6bf48127`. Applying it to the PyPI source
archive has not yet been verified; the PyPI archive should not be treated as a
drop-in patching fallback until that check is completed.

## Citation

Hydra accompanies the paper *Automating Attack Graph Construction for Agentic
Pentesting: Towards Neuro-Symbolic Vulnerability Hunting*, presented at the
[RAISE Workshop at ESORICS 2026](https://raise-workshop.github.io/).

```bibtex
@inproceedings{Stevanovic2026,
  author = {Stevanovic, Oliver and Wachter, Jasmin},
  title = {Automating Attack Graph Construction for Agentic Pentesting: Towards Neuro-Symbolic Vulnerability Hunting},
  booktitle = {Proceedings of the RAISE Workshop at ESORICS},
  year = {2026}
}
```

## Acknowledgements

We thank [takeoff30](https://github.com/takeoff30) for contributions to Hydra.
Because this public repository was created as a clean, history-free release
snapshot, those contributions are not represented in its Git commit history.
