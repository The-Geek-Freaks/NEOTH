#!/usr/bin/env bash
# NEOTH launch — verifies the signed GitHub release and posts one announcement.
# The release workflow is triggered by pushing the release tag; run this only
# after that tag points at the reviewed commit.
#
#   bash scripts/launch.sh v1.0.0 publish-v1.0.0
#
# A third argument can select a different release-notes file.
set -euo pipefail

REPO="The-Geek-Freaks/NEOTH"
TAG="${1:-}"
CONFIRM="${2:-}"
NOTES_FILE="${3:-docs/release-notes-v1.0.md}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  echo "Usage: bash scripts/launch.sh <vMAJOR.MINOR.PATCH[-PRERELEASE]> publish-<tag> [notes-file]" >&2
  exit 2
}

[[ "$TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] || usage
if [[ "$TAG" == *-* ]]; then
  IFS='.' read -r -a PRERELEASE_PARTS <<< "${TAG#*-}"
  for PART in "${PRERELEASE_PARTS[@]}"; do
    if [[ "$PART" =~ ^[0-9]+$ && ${#PART} -gt 1 && "$PART" == 0* ]]; then
      echo "error: numeric prerelease identifiers must not have leading zeroes: $TAG" >&2
      exit 2
    fi
  done
fi
if [[ "$CONFIRM" != "publish-$TAG" ]]; then
  echo "error: confirmation must be exactly publish-$TAG" >&2
  exit 2
fi
if [[ ! -s "$NOTES_FILE" ]]; then
  echo "error: release notes are missing or empty: $NOTES_FILE" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: refusing to launch from a dirty worktree" >&2
  exit 1
fi

TAG_COMMIT="$(git rev-parse -q --verify "refs/tags/$TAG^{commit}" 2>/dev/null || true)"
HEAD_COMMIT="$(git rev-parse HEAD)"
if [[ -z "$TAG_COMMIT" ]]; then
  echo "error: local tag $TAG does not exist; create and push the reviewed tag first" >&2
  exit 1
fi
if [[ "$TAG_COMMIT" != "$HEAD_COMMIT" ]]; then
  echo "error: $TAG points at $TAG_COMMIT, but HEAD is $HEAD_COMMIT" >&2
  exit 1
fi

export RELEASE_TAG="$TAG"
python - <<'PY'
import json
import os
import pathlib
import tomllib

tag = os.environ["RELEASE_TAG"]
expected = tag[1:]
manifests = {
    "neoth": pathlib.Path("SRC/neothd/Cargo.toml"),
    "neothd-gui": pathlib.Path("SRC/neothd-gui/Cargo.toml"),
    "neoth-migrate": pathlib.Path("SRC/neoth-migrate/Cargo.toml"),
    "neoth-relay": pathlib.Path("SRC/neoth-relay/Cargo.toml"),
}
loaded = {
    name: tomllib.loads(path.read_text(encoding="utf-8"))
    for name, path in manifests.items()
}
versions = {name: manifest["package"]["version"] for name, manifest in loaded.items()}
versions["whatsapp-baileys-bridge"] = json.loads(
    pathlib.Path("bridges/whatsapp-baileys/package.json").read_text(encoding="utf-8")
)["version"]
mismatches = [
    f"{name}={version}" for name, version in versions.items() if version != expected
]
if mismatches:
    raise SystemExit(
        f"tag {tag} requires version {expected}; mismatched manifests: "
        + ", ".join(mismatches)
    )
sdk = tomllib.loads(
    pathlib.Path("SRC/neoth-plugin-sdk/Cargo.toml").read_text(encoding="utf-8")
)
sdk_dependency = loaded["neoth"]["dependencies"]["neoth-plugin-sdk"]
if sdk_dependency.get("version") != sdk["package"]["version"]:
    raise SystemExit(
        "core SDK dependency version does not match the SDK manifest: "
        f"{sdk_dependency.get('version')} != {sdk['package']['version']}"
    )
if sdk_dependency.get("path") != "../neoth-plugin-sdk":
    raise SystemExit("core SDK dependency must retain the workspace path")
if "_host" not in sdk_dependency.get("features", []):
    raise SystemExit("core SDK dependency must enable the _host integration feature")
print(
    f"release version contract OK: {tag} == "
    + " == ".join(versions)
    + f"; neoth-plugin-sdk={sdk['package']['version']}"
)
PY

gh auth status --hostname github.com >/dev/null

echo "==> NEOTH $TAG launch from $HEAD_COMMIT"

# Never create a source-only release here. The tag-triggered release workflow
# owns builds, signatures, checksums, and publication. If it is still running,
# wait for that exact tag + commit; if it failed, fail closed before announcing.
if gh release view "$TAG" -R "$REPO" >/dev/null 2>&1; then
  echo "--> release $TAG already exists"
else
  RUN_ID="$(gh run list \
    -R "$REPO" \
    --workflow release.yml \
    --event push \
    --limit 100 \
    --json databaseId,headBranch,headSha \
    --jq ".[] | select(.headBranch == \"$TAG\" and .headSha == \"$HEAD_COMMIT\") | .databaseId" \
    | head -n 1)"
  if [[ -z "$RUN_ID" ]]; then
    echo "error: no release workflow run exists for $TAG at $HEAD_COMMIT" >&2
    echo "       push the reviewed tag and let release.yml publish signed artifacts" >&2
    exit 1
  fi
  echo "--> waiting for release workflow run $RUN_ID"
  gh run watch "$RUN_ID" -R "$REPO" --exit-status
fi

RELEASE_JSON="$(mktemp)"
trap 'rm -f "$RELEASE_JSON"' EXIT
gh release view "$TAG" -R "$REPO" --json assets,isPrerelease >"$RELEASE_JSON"
export RELEASE_JSON
if [[ "$TAG" == *-* ]]; then
  export EXPECTED_PRERELEASE=true
else
  export EXPECTED_PRERELEASE=false
fi
python - <<'PY'
import json
import os
import pathlib

payload = json.loads(pathlib.Path(os.environ["RELEASE_JSON"]).read_text(encoding="utf-8"))
expected_prerelease = os.environ["EXPECTED_PRERELEASE"] == "true"
if payload.get("isPrerelease") is not expected_prerelease:
    raise SystemExit(
        "release prerelease state does not match the tag: "
        f"expected {expected_prerelease}, got {payload.get('isPrerelease')!r}"
    )

names = {asset.get("name", "") for asset in payload.get("assets", [])}
required = {"SHA256SUMS", "NEOTH_RELEASE_MINISIGN_PUBKEY.txt"}
missing = sorted(required - names)
archives = sorted(
    name for name in names if name.endswith(".tar.gz") or name.endswith(".zip")
)
tag = os.environ["RELEASE_TAG"]
if not any(name.startswith(f"neoth-{tag}-") for name in archives):
    missing.append(f"neoth-{tag}-<platform archive>")
for archive in archives:
    for suffix in (".sha256", ".cosign.bundle", ".minisig"):
        companion = archive + suffix
        if companion not in names:
            missing.append(companion)
if missing:
    raise SystemExit(
        "release artifact contract is incomplete; missing: " + ", ".join(missing)
    )
print(
    f"release artifact contract OK: {len(archives)} signed archive(s), "
    f"prerelease={expected_prerelease}"
)
PY

TITLE="NEOTH ${TAG#v} is public — start here"
NOTES_URL="https://github.com/$REPO/blob/$TAG/$NOTES_FILE"
DISC_URL="$(gh api graphql \
  -f query='{repository(owner:"The-Geek-Freaks",name:"NEOTH"){discussions(first:100){nodes{title url}}}}' \
  --jq ".data.repository.discussions.nodes | map(select(.title == \"$TITLE\"))[0].url // \"\"")"

if [[ -n "$DISC_URL" ]]; then
  echo "--> discussion already exists, skipping: $DISC_URL"
else
  REPO_ID="$(gh api graphql \
    -f query='{repository(owner:"The-Geek-Freaks",name:"NEOTH"){id}}' \
    --jq '.data.repository.id')"
  CAT_ID="$(gh api graphql \
    -f query='{repository(owner:"The-Geek-Freaks",name:"NEOTH"){discussionCategories(first:20){nodes{name id}}}}' \
    --jq '.data.repository.discussionCategories.nodes[] | select(.name=="Announcements") | .id')"
  if [[ -z "$REPO_ID" || -z "$CAT_ID" ]]; then
    echo "error: repository or Announcements discussion category was not found" >&2
    exit 1
  fi

  BODY="$(cat <<EOF
NEOTH ${TAG#v} is a local-first personal AI daemon in Rust: one memory, three brain paths, five memory tiers plus your vault, and a signed audit log for every sensitive action.

New here? Three good first steps:
- Read the [15-minute verify-it-yourself path](https://github.com/$REPO/blob/main/docs/evaluation.md).
- Skim the README's "Why it holds up" section.
- Install it, then run \`neoth doctor\`.

This is the release where outside eyes matter most. What I would most value:
- Tear apart the [Babel-Index collapse model](https://github.com/$REPO/blob/main/docs/babel-index.md).
- Tell me where the DAU/pro split fails for you.
- File any claim that does not reproduce.

Release: https://github.com/$REPO/releases/tag/$TAG
Release notes: $NOTES_URL
EOF
)"

  echo "--> posting Discussions announcement"
  DISC_URL="$(gh api graphql \
    -f query='mutation($r:ID!,$c:ID!,$t:String!,$b:String!){createDiscussion(input:{repositoryId:$r,categoryId:$c,title:$t,body:$b}){discussion{url}}}' \
    -f r="$REPO_ID" -f c="$CAT_ID" -f t="$TITLE" -f b="$BODY" \
    --jq '.data.createDiscussion.discussion.url')"
  echo "    discussion: $DISC_URL"
fi

echo
echo "==> Done. Browser-only follow-ups:"
echo "  1. Pin the announcement: $DISC_URL"
echo "  2. Social preview: https://github.com/$REPO/settings"
echo "  3. Show HN + Reddit: use PLAN/LAUNCH_KIT.md"
echo
echo "Release: https://github.com/$REPO/releases/tag/$TAG"
