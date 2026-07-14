# Generated WinGet package manifests for NEOTH

This directory intentionally contains no hand-written submit-ready YAML.
`packaging/generate_release_manifests.py` generates the three WinGet manifests
from the exact Windows Setup executables, their bound SHA-256 sidecars, and the
shared native-package metadata contract. The release workflow runs that
generator only after both signed Windows installers pass native
install/upgrade/uninstall smoke tests.

The command below is the post-submission contract; it is not live yet:

```powershell
winget install TheGeekFreaks.NEOTH
```

## Status

**Generated, not yet submitted.** The stable tag/assets do not exist yet. Do
not claim `winget install` works until the generated manifest bundle from the
published release has passed `winget validate` and its PR is merged upstream.

Submission path:

1. Publish the explicitly approved release tag through the protected,
   exact-head release workflow.
2. Download `neoth-package-manifests-vX.Y.Z.zip` from that release and verify
   its SHA-256 plus minisign/cosign companions.
3. Extract `winget/` and run `winget validate --manifest winget\`.
4. Open the PR to [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs):
   `manifests/t/TheGeekFreaks/NEOTH/X.Y.Z/` with all three YAMLs:
   - `TheGeekFreaks.NEOTH.installer.yaml`
   - `TheGeekFreaks.NEOTH.yaml` (version manifest)
   - `TheGeekFreaks.NEOTH.locale.en-US.yaml` (locale + metadata)
5. Once merged, the `winget install` one-liner works.

## Local validation

Fixture-level generator checks do not need a release:

```powershell
python packaging\tests\test_generate_release_manifests.py
```

After a real release, validate the extracted generated bundle:

```powershell
winget validate --manifest .\winget\
```

This requires the [winget client](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
already installed (it ships with Windows 11 + recent Windows 10 builds).
