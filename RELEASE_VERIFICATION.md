# Release verification checkpoint

Recorded: 2026-08-26

## CAI baseline and patch

- Upstream repository: `https://github.com/aliasrobotics/cai`
- CAI version: `0.5.5`
- Upstream commit: `6d47ccc2d282d6ec42243aa524019adb6bf48127`
- Patch: `patches/cai-0.5.5-hydra.patch`
- Patch SHA-256: `BCD203CA619DAECB4DDBCC1E3FFDE3D2383ED4ECE90A57DE1590CD91B2C78568`
- Patch size: `938595` bytes

## Verified

- The patch applies to a clean checkout of the exact upstream commit.
- Python compilation completed successfully.
- MulVAL imports completed successfully.
- Hybrid-service import completed successfully.
- CAI CLI import and `--help` completed successfully.
- Mocked hybrid `Runner.run` orchestration completed successfully.
- Mocked scanner invocation completed successfully without launching scanners.
- Fixture-based predicate generation completed successfully and produced 15 predicates.
- MulVAL unit tests after moving the retained integration to repository-root
  `MulVAL/`: `85 passed` on Python 3.12.4.
- Refreshed patch content matched all 35 selected CAI/Hydra files after
  line-ending normalization.
- Focused direct-Semgrep, Trivy initialization, and local MulVAL rendering
  tests: `4 passed` on Python 3.12.4.
- Real Semgrep, Trivy, and Nmap smoke scans completed successfully.
- Real MulVAL/XSB trace and attack-graph generation completed successfully.
- A live local-model hybrid-agent smoke test completed successfully.

## Public layout verification

- The unchanged upstream CAI source tree is not bundled.
- `requirements.txt` pins `cai-framework==0.5.5`.
- The container build fetches the exact upstream commit, verifies the patch
  SHA-256, checks that the patch applies, and installs the patched checkout.
- All 28 retained `MulVAL/` patch files matched the pristine patched checkout
  after line-ending normalization.
- Docker Compose configuration validation and Python source compilation passed.

## Deferred experimental verification

- Experimental ablations.

If subsequent work changes a CAI-derived file, refresh the patch and repeat the clean-checkout verification before release.
