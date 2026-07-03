#!/usr/bin/env bash
# NEOTH launch — fires every GitHub-native placement in one run.
# Run it yourself so it acts under YOUR authority (the agent is gated from
# publishing public surfaces):
#
#     bash scripts/launch.sh
#
# or from the Claude Code prompt:  ! bash /c/Users/Shadow-PC/CascadeProjects/AGENTER/scripts/launch.sh
#
# Idempotent-ish: skips the release if the tag already exists. Requires `gh`
# authenticated (it already is on this machine).
set -uo pipefail

REPO="The-Geek-Freaks/NEOTH"
TAG="v1.0.0-beta.3"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

echo "==> NEOTH launch from $ROOT"

# 1) Publish the pre-release (source tarball auto-attaches; binaries later).
if gh release view "$TAG" -R "$REPO" >/dev/null 2>&1; then
  echo "--> release $TAG already exists, skipping"
else
  echo "--> publishing release $TAG"
  gh release create "$TAG" \
    -R "$REPO" \
    --title "NEOTH 1.0.0-beta.3 — first public release candidate" \
    --notes-file PLAN/RELEASE_NOTES_beta3.md \
    --prerelease --target main
fi

# 2) Post + pin the Discussions announcement (Announcements category).
echo "--> posting Discussions announcement"
REPO_ID="$(gh api graphql -f query='{repository(owner:"The-Geek-Freaks",name:"NEOTH"){id}}' --jq '.data.repository.id')"
CAT_ID="$(gh api graphql -f query='{repository(owner:"The-Geek-Freaks",name:"NEOTH"){discussionCategories(first:20){nodes{name id}}}}' \
  --jq '.data.repository.discussionCategories.nodes[] | select(.name=="Announcements") | .id')"
BODY='NEOTH is a local-first personal AI daemon in Rust: one memory, three brain paths, five memory tiers + your vault, and a signed audit log for every sensitive action.

New here? Three good first steps:
- Read the 15-minute verify-it-yourself path: [docs/evaluation.md](https://github.com/The-Geek-Freaks/NEOTH/blob/main/docs/evaluation.md)
- Skim why it holds up: the README "Why it holds up" section
- Try it: the source bootstrap in the README, then `neoth doctor`

This is the release where outside eyes matter most. What I'"'"'d most value:
- Tear apart the Babel-Index collapse model ([docs/babel-index.md](https://github.com/The-Geek-Freaks/NEOTH/blob/main/docs/babel-index.md))
- Tell me where the DAU/pro split fails for you
- File any claim that does not reproduce — that is the highest-value issue here'
DISC_URL="$(gh api graphql \
  -f query='mutation($r:ID!,$c:ID!,$t:String!,$b:String!){createDiscussion(input:{repositoryId:$r,categoryId:$c,title:$t,body:$b}){discussion{url}}}' \
  -f r="$REPO_ID" -f c="$CAT_ID" -f t="NEOTH is public — start here" -f b="$BODY" \
  --jq '.data.createDiscussion.discussion.url' 2>/dev/null)"
echo "    discussion: ${DISC_URL:-(failed — post manually via the URL below)}"

echo ""
echo "==> Done with the automatable parts. Two browser-only steps left:"
echo "  1. Social preview  : https://github.com/$REPO/settings  (General -> Social preview -> upload .github/assets/neoth-social-preview.png)"
echo "  2. Show HN + Reddit: paste from PLAN/LAUNCH_KIT.md  (Tue-Thu ~15:00 UTC) — this is the real traction trigger"
echo ""
echo "Release: https://github.com/$REPO/releases/tag/$TAG"
