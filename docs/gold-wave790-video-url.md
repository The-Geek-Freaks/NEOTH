# Explicit video URL ingestion

`neoth ingest --video-url "https://example.com/video"` retrieves subtitles
before attempting a media download. A local file remains the positional input;
the CLI requires exactly one of that file and `--video-url`.

Install the pinned managed yt-dlp release through the interactive `neoth init`
offer. The installer checks the published SHA-256 and version, and ingestion
verifies the managed executable before using it. The installer never invokes
a package manager. The pinned release metadata is the upstream yt-dlp
`2026.08.19` GitHub release.

Each subtitle request passes through NEOTH's existing request-bound permission
gate and appends `VideoDownloadConsented` before starting the downloader. A
missing subtitle leads to a separate authorization and audit for the media
fallback. Refused authorization or failed required audit prevents that
transport. `--no-audit` is consequently incompatible with URL ingestion.

Successful subtitles feed the normal ingestion result and recall-indexing
path. The fallback uses the existing local video extractor. Existing
`--no-index` and `--no-persist` options retain their respective meanings.
Persisted source labels use `video-url:<sha256>` rather than the raw URL.

The downloader has a 120-second deadline. NEOTH monitors the aggregate staging
directory while it runs and kills and reaps the child when it observes more
than 2 MiB of subtitle output or 256 MiB of downloaded media. This monitoring
is not an operating-system disk quota; the downloader can write between
checks. Output is validated again before the next consumer reads it.

The implementation has an independent source review and hermetic test
selectors for installer identity, bounded downloads, caption-first ordering,
separate fallback permission, audit refusal, staging limits and CLI input
exclusivity. Their executable results are recorded separately by the hosted
GOLD test lane; source review alone does not close ADOPT31-F4.
