# W333 — managed-browser policy and capability-bound resolver

**Scope completed:** typed configuration, checked-in reviewed manifest, and a
side-effect-free explicit-home resolver. This slice does not download, unpack,
install, launch, attach to, or navigate a browser.

## Policy and admitted manifest

FreedomConfig has a typed managed_browser section with a default-off enabled
flag. A manifest or installed generation never enables rendered fetch itself.

The compact manifest embeds the four artifacts admitted by hosted run
35839698279. Every entry binds exact archive hash, executable path, executable
length/hash and the one exact CFT URL:

| Target | Archive SHA-256 | Executable |
| --- | --- | --- |
| win64 | bcc91b4d0f83a5457fc6ca7941fd65f2349775523d961be88526c6a66560dc75 | chrome-headless-shell-win64/chrome-headless-shell.exe |
| linux64 | 5a6979d0ab7cf952ea575d35164e7bdce4872b2ced8f8a215c8f8e8eda00ee09 | chrome-headless-shell-linux64/chrome-headless-shell |
| mac-x64 | b3f9551d90c9ff0f4c7c231a4dbf226b3c64faba8ced1ab61a5ef9d430d0e996 | chrome-headless-shell-mac-x64/chrome-headless-shell |
| mac-arm64 | 9ba4d8a9732bd7e431ce9009d1bbe1ccf7f8c5de2a9781054f500a9fe898124d | chrome-headless-shell-mac-arm64/chrome-headless-shell |

It records CFT 154.0.8037.57 / revision 1689415, hosted source head
a41946046158991115b0380af7beb873f93f8092, and admission receipt digest
eef1d3aa4ce66ed1d1fe5703c38feeabaa20f064b3105625807a3d41dcfb67e9.

## Capability-bound resolver contract

ManagedBrowserRuntimeResolver receives an explicit NEOTH home, explicit
target and typed configuration. It does not infer platform or storage
location. It opens the home and every child through existing cap-std no-follow
directory capabilities and retains direct-child identity bindings:

    <home>/managed-browser/generations/<platform>-<version>-<archive-sha256>/
      .neoth-managed-browser-generation.json
      chrome-headless-shell-<platform>/<reviewed executable>

The marker repeats schema, target, CFT version/revision, archive digest and
executable digest/length. The resolver rejects disabled policy, missing
components, forged/unsupported manifest, nonexact target URL, unsafe paths,
symlink/junction/reparse entries, malformed marker, wrong length and wrong
digest. It hashes the opened executable handle once in a bounded stream.

ResolvedManagedBrowser retains its no-follow directory capabilities and
regular-file identity binding. Its revalidate_for_launch method reopens each
direct child through its retained parent capability and refuses any namespace
or executable replacement. This prevents check/open and path-return races at
the resolver handoff.

The method is deliberately a revalidation seam, not a launch primitive. The
future contained launcher must call it immediately before its final
OS-specific launch preparation, keep the retained binding alive through that
preparation, and refuse a mismatch. Its own command-creation semantics remain
a separate reviewed implementation concern; W333 does not claim final launch
safety before that code exists.

No PATH, HOME, USERPROFILE, registry, installed-browser, download cache,
network, archive or browser launcher is consulted.

## Downstream installer contract

The installer retrieves only the exact reviewed URL, records source/feed
identity and retrieval time, verifies archive SHA-256 before unpacking,
validates the reviewed executable path/length/SHA-256, writes the marker into
an immutable generation, then publishes pointer-last. Update/repair retains
the previous verified generation until successful publication. Uninstall
revokes only managed data.

Browser containment, private CDP attachment, egress mediation and rendered
navigation stay in later slices. This resolver is the accepted executable
handoff only; it establishes no runtime acceptance.
