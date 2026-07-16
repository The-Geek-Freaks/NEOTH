# NEOTH distribution metadata

Do not add versioned package-manager manifests below this directory.
Checked-in templates cannot know the final release asset hashes and previously
left an obsolete `0.2.1` WinGet manifest with a placeholder digest in the tree.

The only WinGet/Homebrew manifest authority is
`packaging/generate_release_manifests.py`. The release workflow runs it after
all native artifacts, metadata and SHA-256 sidecars exist, then content-tests
the generated archive before publication. Current Windows manifests target the
signed Inno Setup executables for both supported architectures and list the full
installed command set.

Bootstrap scripts live at `scripts/install.sh` and `scripts/install.ps1`.
Native package builders and their clean-machine contracts live under
`packaging/windows`, `packaging/macos` and `packaging/linux`.
