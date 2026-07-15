#!/usr/bin/env python3
"""Pin the clean-machine installer verifier to one reviewed Sigstore source."""

from __future__ import annotations

import io
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import warnings
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = json.loads(
    (ROOT / "packaging/cosign-bootstrap.json").read_text(encoding="utf-8")
)
UNIX = (ROOT / "SRC/install.sh").read_text(encoding="utf-8")
WINDOWS = (ROOT / "SRC/install.ps1").read_text(encoding="utf-8")
RELEASE = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
INTERNAL = (ROOT / "SRC/neothd/src/cli/internal.rs").read_text(encoding="utf-8")
CLI = (ROOT / "SRC/neothd/src/cli/mod.rs").read_text(encoding="utf-8")
RELEASE_BUNDLE = (
    ROOT / "SRC/neothd/src/updater/release_bundle.rs"
).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"bootstrap verifier contract failed: {message}")


def capture(text: str, pattern: str, label: str) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    require(match is not None, f"missing {label}")
    return match.group(1)


ArchiveEntry = tuple[str, str, bytes | str]


def archive_cases() -> dict[str, list[ArchiveEntry]]:
    root: ArchiveEntry = ("dir", "root/", b"")
    return {
        "valid": [root, ("file", "root/neoth", b"ok")],
        "empty": [],
        "no_file": [root],
        "missing_explicit_root": [("file", "root/neoth", b"ok")],
        "traversal": [root, ("file", "root/../escape", b"x")],
        "absolute": [root, ("file", "/root/escape", b"x")],
        "drive": [root, ("file", "C:/escape", b"x")],
        "backslash": [root, ("file", "root\\escape", b"x")],
        "double_separator": [root, ("file", "root//escape", b"x")],
        "wrong_root": [root, ("file", "other/escape", b"x")],
        "duplicate": [
            root,
            ("file", "root/neoth", b"one"),
            ("file", "root/neoth", b"two"),
        ],
        "casefold_collision": [
            root,
            ("file", "root/Node", b"one"),
            ("file", "root/node", b"two"),
        ],
        "file_directory_conflict": [
            root,
            ("file", "root/node", b"one"),
            ("file", "root/node/child", b"two"),
        ],
        "depth_ceiling": [root, ("file", "root/a/b/c/d", b"x")],
        "member_ceiling": [root, ("file", "root/large", b"123456789")],
        "total_ceiling": [
            root,
            ("file", "root/one", b"1234567"),
            ("file", "root/two", b"1234567"),
        ],
        "entry_ceiling": [
            root,
            *(("file", f"root/{index}", b"x") for index in range(8)),
        ],
        "symlink": [root, ("symlink", "root/link", "root/neoth")],
        "fifo": [root, ("fifo", "root/pipe", b"")],
        "directory_data": [root, ("directory_data", "root/data/", b"x")],
    }


def write_tar(path: pathlib.Path, entries: list[ArchiveEntry]) -> None:
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
        for kind, name, payload in entries:
            member = tarfile.TarInfo(name)
            member.uid = 0
            member.gid = 0
            member.mtime = 1
            if kind in {"dir", "directory_data"}:
                data = payload if isinstance(payload, bytes) else payload.encode()
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                member.size = len(data) if kind == "directory_data" else 0
                archive.addfile(member, io.BytesIO(data) if data else None)
            elif kind == "file":
                data = payload if isinstance(payload, bytes) else payload.encode()
                member.type = tarfile.REGTYPE
                member.mode = 0o644
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = str(payload)
                archive.addfile(member)
            elif kind == "hardlink":
                member.type = tarfile.LNKTYPE
                member.linkname = str(payload)
                archive.addfile(member)
            elif kind == "fifo":
                member.type = tarfile.FIFOTYPE
                archive.addfile(member)
            else:
                raise AssertionError(f"unknown tar fixture kind: {kind}")


def write_zip(path: pathlib.Path, entries: list[ArchiveEntry]) -> None:
    with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as archive:
        warnings.simplefilter("ignore", UserWarning)
        for kind, name, payload in entries:
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.date_time = (1980, 1, 1, 0, 0, 0)
            member.compress_type = zipfile.ZIP_DEFLATED
            data = payload if isinstance(payload, bytes) else payload.encode()
            dos_attributes = 0
            if kind in {"dir", "directory_data"}:
                mode = stat.S_IFDIR | 0o755
                dos_attributes = 0x10
                if kind == "dir":
                    data = b""
            elif kind == "file":
                mode = stat.S_IFREG | 0o644
            elif kind == "symlink":
                mode = stat.S_IFLNK | 0o777
            elif kind == "fifo":
                mode = stat.S_IFIFO | 0o644
            elif kind == "reparse":
                mode = stat.S_IFREG | 0o644
                dos_attributes = 0x400
            else:
                raise AssertionError(f"unknown ZIP fixture kind: {kind}")
            member.external_attr = ((mode & 0xFFFF) << 16) | dos_attributes
            archive.writestr(member, data)
    # zipfile canonicalizes '\\' to '/' on Windows. Re-introduce the raw byte
    # in both local and central names so the platform-independent contract test
    # exercises the archive bytes an attacker can actually publish.
    raw_archive = path.read_bytes()
    for _, name, _ in entries:
        if "\\" in name:
            raw_archive = raw_archive.replace(
                name.replace("\\", "/").encode(),
                name.encode(),
            )
    path.write_bytes(raw_archive)


def find_bash() -> str | None:
    candidates: list[str | None] = []
    if os.name == "nt":
        candidates.extend(
            [
                r"C:\Program Files\Git\bin\bash.exe",
                r"C:\Program Files\Git\usr\bin\bash.exe",
            ]
        )
    candidates.append(shutil.which("bash"))
    return next((str(path) for path in candidates if path and pathlib.Path(path).is_file()), None)


def bash_script_path(path: pathlib.Path) -> str:
    value = str(path.resolve())
    if os.name != "nt":
        return value
    drive, tail = os.path.splitdrive(value)
    return f"/{drive[0].lower()}{tail.replace(os.sep, '/')}"


def run_bash_adversarial_tests() -> int:
    bash = find_bash()
    require(bash is not None, "Bash is required for archive preflight fixtures")
    prefix = UNIX.split("# ── Main", 1)[0]
    with tempfile.TemporaryDirectory(prefix="neoth-bootstrap-tar-") as raw_temp:
        base = pathlib.Path(raw_temp)
        scratch = base / "scratch"
        scratch.mkdir()
        runner = base / "archive-runner.sh"
        runner.write_text(
            prefix
            + r'''
to_shell_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -u "$1"
    else
        printf '%s\n' "$1"
    fi
}
TMP="$(to_shell_path "${NEOTH_TEST_TMP:?}")"
archive="$(to_shell_path "${NEOTH_TEST_ARCHIVE:?}")"
destination="$(to_shell_path "${NEOTH_TEST_DESTINATION:?}")"
if [ -n "${NEOTH_TEST_PATH_PREFIX:-}" ]; then
    PATH="$(to_shell_path "$NEOTH_TEST_PATH_PREFIX"):$PATH"
    export PATH
    hash -r
fi
MAX_ARCHIVE_ENTRIES=8
MAX_ARCHIVE_DEPTH=3
MAX_ARCHIVE_MEMBER_BYTES=8
MAX_ARCHIVE_TOTAL_BYTES=12
MAX_ARCHIVE_LISTING_BYTES=1048576
MAX_ARCHIVE_RECORDS="${NEOTH_TEST_MAX_RECORDS:-500000}"
MAX_ARCHIVE_RECORD_BYTES="${NEOTH_TEST_MAX_RECORD_BYTES:-67108864}"
preflight_tar_archive "$archive" root "$destination"
printf 'ARCHIVE_OK\n'
''',
            encoding="utf-8",
        )
        cases = archive_cases()
        cases["hardlink"] = [
            ("dir", "root/", b""),
            ("file", "root/neoth", b"ok"),
            ("hardlink", "root/hard", "root/neoth"),
        ]
        cases["derived_record_ceiling"] = [
            ("dir", "root/", b""),
            ("file", "root/a/b/c", b"x"),
        ]
        cases["derived_record_byte_ceiling"] = [
            ("dir", "root/", b""),
            ("file", "root/abcd", b"x"),
        ]
        for name, entries in cases.items():
            archive = base / f"{name}.tar.gz"
            destination = base / f"out-{name}"
            write_tar(archive, entries)
            environment = os.environ.copy()
            environment.update(
                {
                    "NEOTH_TEST_TMP": str(scratch),
                    "NEOTH_TEST_ARCHIVE": str(archive),
                    "NEOTH_TEST_DESTINATION": str(destination),
                }
            )
            if name == "derived_record_ceiling":
                environment["NEOTH_TEST_MAX_RECORDS"] = "4"
            elif name == "derived_record_byte_ceiling":
                environment["NEOTH_TEST_MAX_RECORD_BYTES"] = "10"
            result = subprocess.run(
                [bash, bash_script_path(runner)],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
                timeout=30,
            )
            accepted = name == "valid"
            require(
                (result.returncode == 0) == accepted,
                f"Unix tar case {name} returned {result.returncode}: {result.stderr.strip()}",
            )
            if accepted:
                require(
                    (destination / "root/neoth").read_bytes() == b"ok",
                    "Unix valid tar did not extract exact bytes",
                )

        bsdtar_cases = 0
        if os.name == "nt":
            windows_tar = (
                pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
                / "System32/tar.exe"
            )
            if windows_tar.is_file():
                version_result = subprocess.run(
                    [str(windows_tar), "--version"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if "bsdtar" in version_result.stdout:
                    bsdtar_bin = base / "bsdtar-bin"
                    bsdtar_bin.mkdir()
                    tar_wrapper = bsdtar_bin / "tar"
                    tar_wrapper.write_text(
                        "#!/usr/bin/env bash\n"
                        f'exec "{bash_script_path(windows_tar)}" "$@"\n',
                        encoding="utf-8",
                    )
                    tar_wrapper.chmod(0o755)
                    for name in (
                        "valid",
                        "traversal",
                        "absolute",
                        "backslash",
                        "member_ceiling",
                        "symlink",
                        "hardlink",
                    ):
                        destination = base / f"out-bsdtar-{name}"
                        environment = os.environ.copy()
                        environment.update(
                            {
                                "NEOTH_TEST_TMP": str(scratch),
                                "NEOTH_TEST_ARCHIVE": str(base / f"{name}.tar.gz"),
                                "NEOTH_TEST_DESTINATION": str(destination),
                                "NEOTH_TEST_PATH_PREFIX": str(bsdtar_bin),
                            }
                        )
                        result = subprocess.run(
                            [bash, bash_script_path(runner)],
                            check=False,
                            capture_output=True,
                            env=environment,
                            text=True,
                            timeout=30,
                        )
                        accepted = name == "valid"
                        require(
                            (result.returncode == 0) == accepted,
                            f"bsdtar case {name} returned {result.returncode}: {result.stderr.strip()}",
                        )
                        bsdtar_cases += 1

        stream_runner = base / "stream-runner.sh"
        stream_runner.write_text(
            prefix
            + r'''
to_shell_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -u "$1"; else printf '%s\n' "$1"; fi
}
destination="$(to_shell_path "${NEOTH_TEST_DESTINATION:?}")"
if bounded_stream_to_file "$destination" 8; then
    printf 'STREAM_OK\n'
else
    exit 23
fi
''',
            encoding="utf-8",
        )
        exact = base / "stream-exact"
        exact_result = subprocess.run(
            [bash, bash_script_path(stream_runner)],
            input=b"12345678",
            check=False,
            capture_output=True,
            env={**os.environ, "NEOTH_TEST_DESTINATION": str(exact)},
            timeout=30,
        )
        require(exact_result.returncode == 0 and exact.read_bytes() == b"12345678", "Unix stream cap rejects exact ceiling")
        over = base / "stream-over"
        over_result = subprocess.run(
            [bash, bash_script_path(stream_runner)],
            input=b"123456789",
            check=False,
            capture_output=True,
            env={**os.environ, "NEOTH_TEST_DESTINATION": str(over)},
            timeout=30,
        )
        require(
            over_result.returncode != 0 and not over.exists() and not pathlib.Path(f"{over}.part").exists(),
            "Unix stream cap accepted or retained a MAX+1 response without Content-Length",
        )
        return len(cases) + bsdtar_cases + 2


def find_powershell() -> str | None:
    candidates = [shutil.which("pwsh"), shutil.which("powershell")]
    if os.name == "nt":
        candidates.append(
            str(
                pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows"))
                / "System32/WindowsPowerShell/v1.0/powershell.exe"
            )
        )
    return next((str(path) for path in candidates if path and pathlib.Path(path).is_file()), None)


def run_powershell_adversarial_tests() -> int:
    powershell = find_powershell()
    if powershell is None:
        return 0
    prefix = WINDOWS.split("# ── Main", 1)[0]
    with tempfile.TemporaryDirectory(prefix="neoth-bootstrap-zip-") as raw_temp:
        base = pathlib.Path(raw_temp)
        cases = archive_cases()
        cases.update(
            {
                "reparse": [("dir", "root/", b""), ("reparse", "root/link", b"x")],
                "normalization_collision": [
                    ("dir", "root/", b""),
                    ("file", "root/é", b"one"),
                    ("file", "root/e\u0301", b"two"),
                ],
                "reserved_device": [
                    ("dir", "root/", b""),
                    ("file", "root/CON.txt", b"x"),
                ],
                "trailing_dot": [
                    ("dir", "root/", b""),
                    ("file", "root/name.", b"x"),
                ],
            }
        )
        manifest: list[dict[str, object]] = []
        for name, entries in cases.items():
            archive = base / f"{name}.zip"
            destination = base / f"out-{name}"
            write_zip(archive, entries)
            manifest.append(
                {
                    "name": name,
                    "archive": str(archive),
                    "destination": str(destination),
                    "accept": name == "valid",
                }
            )
        manifest_path = base / "cases.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        runner = base / "zip-runner.ps1"
        runner.write_text(
            prefix
            + r'''
$failures = New-Object System.Collections.Generic.List[string]
$cases = @([IO.File]::ReadAllText($env:NEOTH_TEST_CASES) | ConvertFrom-Json)
foreach ($case in $cases) {
    try {
        Expand-SafeZipArchive `
            -ArchivePath $case.archive `
            -ExpectedRoot 'root' `
            -DestinationRoot $case.destination `
            -MaxEntries 8 `
            -MaxDepth 3 `
            -MaxMemberBytes 8 `
            -MaxTotalBytes 12
        if (-not $case.accept) { $failures.Add("accepted $($case.name)") }
    } catch {
        if ($case.accept) { $failures.Add("rejected $($case.name): $($_.Exception.Message)") }
    }
}
if ($failures.Count -gt 0) {
    [Console]::Error.WriteLine(($failures -join "`n"))
    exit 23
}
[Console]::Out.WriteLine('ZIP_CASES_OK')
''',
            encoding="utf-8-sig",
        )
        command = [powershell, "-NoLogo", "-NoProfile", "-NonInteractive"]
        if os.name == "nt":
            command.extend(["-ExecutionPolicy", "Bypass"])
        command.extend(["-File", str(runner)])
        # PowerShell Core on Linux has no Windows LOCALAPPDATA default. Bind
        # every installer path used while loading the extracted function prefix
        # to this fixture instead of depending on the host runner environment.
        local_app_data = base / "local-app-data"
        local_app_data.mkdir()
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env={
                **os.environ,
                "LOCALAPPDATA": str(local_app_data),
                "NEOTH_INSTALL_DIR": str(base / "install-root"),
                "NEOTH_TEST_CASES": str(manifest_path),
            },
            text=True,
            timeout=90,
        )
        require(
            result.returncode == 0,
            f"Windows ZIP adversarial cases failed: {result.stderr.strip()}",
        )
        require(
            (base / "out-valid/root/neoth").read_bytes() == b"ok",
            "Windows valid ZIP did not extract exact bytes",
        )
        return len(cases)


require(MANIFEST.get("schema_version") == 1, "unknown manifest schema")
source = MANIFEST.get("source", {})
require(source.get("repository") == "sigstore/cosign-installer", "wrong source repo")
require(re.fullmatch(r"[0-9a-f]{40}", source.get("commit", "")) is not None, "source commit is not immutable")
require(source.get("path") == "action.yml", "wrong digest source path")

version = MANIFEST["cosign_version"]
assets = MANIFEST["assets"]
for platform, asset in assets.items():
    require(re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]) is not None, f"bad {platform} digest")
    require("/" not in asset["name"] and "\\" not in asset["name"], f"unsafe {platform} asset name")

unix_pins = {
    "version": capture(UNIX, r'^COSIGN_BOOTSTRAP_VERSION="([^"]+)"$', "Unix version pin"),
    "linux_amd64": capture(UNIX, r'^COSIGN_BOOTSTRAP_LINUX_AMD64_SHA256="([0-9a-f]+)"$', "Unix linux-amd64 pin"),
    "linux_arm64": capture(UNIX, r'^COSIGN_BOOTSTRAP_LINUX_ARM64_SHA256="([0-9a-f]+)"$', "Unix linux-arm64 pin"),
    "darwin_amd64": capture(UNIX, r'^COSIGN_BOOTSTRAP_DARWIN_AMD64_SHA256="([0-9a-f]+)"$', "Unix darwin-amd64 pin"),
    "darwin_arm64": capture(UNIX, r'^COSIGN_BOOTSTRAP_DARWIN_ARM64_SHA256="([0-9a-f]+)"$', "Unix darwin-arm64 pin"),
}
require(unix_pins["version"] == version, "Unix cosign version drift")
for platform in ("linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"):
    require(unix_pins[platform] == assets[platform]["sha256"], f"Unix {platform} digest drift")
    require(assets[platform]["name"] in UNIX, f"Unix {platform} filename drift")

windows_version = capture(WINDOWS, r"^\$CosignBootstrapVersion = '([^']+)'$", "Windows version pin")
windows_sha = capture(WINDOWS, r"^\$CosignBootstrapWindowsAmd64Sha256 = '([0-9a-f]+)'$", "Windows digest pin")
require(windows_version == version, "Windows cosign version drift")
require(windows_sha == assets["windows_amd64"]["sha256"], "Windows digest drift")
require(assets["windows_amd64"]["name"] in WINDOWS, "Windows filename drift")

unix_bootstrap = UNIX[UNIX.index("resolve_cosign_verifier() {") : UNIX.index("verify_release_authenticity() {")]
unix_download = unix_bootstrap.index("download_file")
unix_hash = unix_bootstrap.index('got="$(sha256_file "$path")"')
unix_execute_ready = unix_bootstrap.index('COSIGN_VERIFIER="$path"')
require(unix_download < unix_hash < unix_execute_ready, "Unix verifier is usable before hash validation")
require('"$COSIGN_VERIFIER" verify-blob' in UNIX, "Unix verification does not use the resolved verifier")
require("eval " not in unix_bootstrap, "Unix bootstrap uses eval")
require(
    "set -euo pipefail" in UNIX
    and "head -c $((max_bytes + 1))" in UNIX
    and '--max-time "$MAX_DOWNLOAD_SECONDS"' in UNIX
    and '| bounded_stream_to_file "$destination" "$max_bytes"' in UNIX,
    "Unix downloads are not stream-capped independently of Content-Length",
)
require(
    "preflight_tar_archive" in UNIX
    and "--absolute-names" in UNIX
    and "MAX_ARCHIVE_RECORDS" in UNIX
    and "MAX_ARCHIVE_RECORD_BYTES" in UNIX
    and "unsupported tar implementation" in UNIX
    and "tar -xzf" not in UNIX,
    "Unix archive extraction bypasses the bounded member preflight",
)
require(
    '"$BINARY_SRC" --output json self-knowledge verify' in UNIX,
    "Unix bootstrap does not run the release binary's closed-set snapshot verifier",
)
unix_native_transaction = (
    '"$BINARY_SRC" --output json internal bundle-transaction apply'
)
require(
    UNIX.index('"$BINARY_SRC" --output json self-knowledge verify')
    < UNIX.index(unix_native_transaction),
    "Unix bootstrap verifies self-knowledge after mutation starts",
)
require(
    'BUNDLE_ROOT="$EXTRACTION_ROOT/$ARCHIVE_NAME"' in UNIX
    and '--bundle-root "$BUNDLE_ROOT"' in UNIX
    and '--install-root "$NEOTH_INSTALL_DIR"' in UNIX
    and '--expected-version "${VERSION#v}"' in UNIX,
    "Unix bootstrap does not invoke the exact native bundle transaction",
)
require(
    "transactional_install() {" not in UNIX
    and "rollback_replaced()" not in UNIX
    and "local -a names sources modes kinds replaced" not in UNIX,
    "Unix bootstrap still carries an independent transaction algorithm",
)
require(
    'BINARY_SRC="$TMP/neoth"' not in UNIX
    and 'mkdir -p "$NEOTH_INSTALL_DIR"' not in UNIX,
    "Unix bootstrap accepts a flat fallback or mutates install root before native lock",
)

windows_bootstrap = WINDOWS[WINDOWS.index("function Resolve-CosignVerifier {") : WINDOWS.index("function Verify-ReleaseAuthenticity {")]
windows_download = windows_bootstrap.index("Invoke-Download -Uri $uri")
windows_hash = windows_bootstrap.index("Get-FileHash -LiteralPath $path -Algorithm SHA256")
windows_return = windows_bootstrap.index("return $path")
require(windows_download < windows_hash < windows_return, "Windows verifier is usable before hash validation")
require("& $cosignPath verify-blob" in WINDOWS, "Windows verification does not use the resolved verifier")
require("https://github.com/sigstore/cosign/releases/download/" in windows_bootstrap, "Windows bootstrap URL is not fixed HTTPS")
require(
    "HttpCompletionOption]::ResponseHeadersRead" in WINDOWS
    and "$written -gt $MaxBytes" in WINDOWS
    and "$MaxDownloadSeconds - $stopwatch.Elapsed.TotalSeconds" in WINDOWS
    and "download redirected outside HTTPS" in WINDOWS,
    "Windows downloads are not stream-capped over absolute HTTPS",
)
require(
    "Expand-SafeZipArchive" in WINDOWS
    and "Read-CanonicalZipCentralNames" in WINDOWS
    and "raw backslash path separator" in WINDOWS
    and "ZipArchiveMode]::Read" in WINDOWS
    and "FileMode]::CreateNew" in WINDOWS
    and "Expand-Archive" not in WINDOWS,
    "Windows ZIP extraction bypasses the bounded manual preflight",
)
require(
    "& $BinarySrc --output json self-knowledge verify --snapshot $SelfKnowledgePath"
    in WINDOWS,
    "Windows bootstrap does not run the release binary's closed-set snapshot verifier",
)
windows_native_transaction = (
    "& $BinarySrc --output json internal bundle-transaction apply"
)
require(
    WINDOWS.index("& $BinarySrc --output json self-knowledge verify --snapshot $SelfKnowledgePath")
    < WINDOWS.index(windows_native_transaction),
    "Windows bootstrap verifies self-knowledge after mutation starts",
)
require(
    "$BundleRoot = Join-Path $ExtractionRoot $ArchiveName" in WINDOWS
    and "--bundle-root $BundleRoot" in WINDOWS
    and "--install-root $InstallDir" in WINDOWS
    and "--expected-version $ExpectedReleaseVersion" in WINDOWS,
    "Windows bootstrap does not invoke the exact native bundle transaction",
)
require(
    "function Install-FileSetTransaction" not in WINDOWS
    and "$installItems = @(" not in WINDOWS
    and "Move-Item -LiteralPath (Join-Path $payload" not in WINDOWS,
    "Windows bootstrap still carries an independent transaction algorithm",
)
require(
    "$BinarySrc = Join-Path $Tmp 'neoth.exe'" not in WINDOWS
    and "New-Item -ItemType Directory -Force -Path $InstallDir" not in WINDOWS,
    "Windows bootstrap accepts a flat fallback or mutates install root before native lock",
)

require('#[command(name = "bundle-transaction")]' in INTERNAL, "native command name drift")
require(
    'if output != OutputFormat::Json' in INTERNAL
    and 'expected_version != env!("CARGO_PKG_VERSION")' in INTERNAL
    and "require_running_bundle_helper(&bundle_root)?" in INTERNAL,
    "hidden helper is not JSON-only and release-binary-bound",
)
require(
    '#[command(hide = true)]' in CLI and "Internal(internal::InternalArgs)" in CLI,
    "internal release surface is public in help or not dispatched",
)
for required in (
    'BundleMemberSpec::file("README.md")',
    'BundleMemberSpec::file("LICENSE-MIT")',
    'BundleMemberSpec::file("LICENSE-APACHE")',
    'BundleMemberSpec::file("THIRD_PARTY_LICENSES")',
    'BundleMemberSpec::file("freedom.yaml.example")',
    'BundleMemberSpec::file("import-manifest.example.yaml")',
    "BundleMemberSpec::directory(SELF_KNOWLEDGE)",
    "VerifiedReleaseSnapshot::open_for_update",
    "PreparedMember::file",
    "PreparedMember::directory",
    "PreparedMember::absent_file",
):
    require(required in RELEASE_BUNDLE, f"native closed bundle policy omits {required}")
require(
    "release bundle contains unexpected entry" in RELEASE_BUNDLE
    and "release bundle is missing required entries" in RELEASE_BUNDLE
    and "metadata_is_link_like" in RELEASE_BUNDLE,
    "native closed bundle policy lacks missing/unexpected/link rejection",
)
require(
    "pub enum ReleaseInstallLayout" in RELEASE_BUNDLE
    and "Portable(PathBuf)" in RELEASE_BUNDLE
    and "LinuxSystem" in RELEASE_BUNDLE
    and "MacApp(PathBuf)" in RELEASE_BUNDLE
    and "pub fn apply_release_bundle" in RELEASE_BUNDLE,
    "self-update cannot reuse the native exact bundle policy across package layouts",
)
for destination in (
    'Path::new("/usr/bin")',
    'Path::new("/usr/share/neoth")',
    'Path::new("/usr/share/doc/neoth/examples")',
):
    require(destination in RELEASE_BUNDLE, f"native package layout omits {destination}")
require(
    "NativeLinuxPackageRequired" in RELEASE_BUNDLE
    and "SignedMacPackageRequired" in RELEASE_BUNDLE
    and "validate_mac_contents(contents)?" in RELEASE_BUNDLE,
    "native package self-update does not fail closed at package-manager/signing boundaries",
)
require(
    "PreparedMember::absent_file(layout.absent_target(gui_binary_name())?)"
    in RELEASE_BUNDLE
    and "PreparedMember::absent_file(layout.absent_target(keet_binary_name())?)"
    in RELEASE_BUNDLE,
    "headless musl transaction does not remove stale desktop companions",
)

action = f"uses: sigstore/cosign-installer@{source['commit']}"
require(action in RELEASE, "release workflow uses a different cosign-installer source")
require(f"cosign-release: '{version}'" in RELEASE, "release workflow does not pin the same cosign version")

unix_adversarial = run_bash_adversarial_tests()
windows_adversarial = run_powershell_adversarial_tests()
print(
    f"bootstrap verifier contract OK: cosign {version}, {len(assets)} pinned assets; "
    f"{unix_adversarial} Unix and {windows_adversarial} Windows archive/stream fixtures"
)
