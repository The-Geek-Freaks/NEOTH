#!/usr/bin/env bash
# Future hosted bootstrap only: creates candidate lockfiles, never native binaries.
set -euo pipefail
: "${FLUTTER_SDK:?pinned Flutter SDK root required}"

repo_root="$(git rev-parse --show-toplevel)"
bridge="$repo_root/bridges/companion-native"
app="$repo_root/apps/neoth_companion"
source_lock="$repo_root/SRC/Cargo.lock"
stage="${1:?bootstrap output directory required}"
sha256() { sha256sum "$1" | awk '{print toupper($1)}'; }

[[ "$GITHUB_REF" == "refs/heads/main" && "$(git rev-parse HEAD)" == "$GITHUB_SHA" ]] || { echo "bootstrap accepts only dispatched main checkout" >&2; exit 64; }
[[ -f "$bridge/Cargo.toml" && -f "$app/pubspec.yaml" && -f "$source_lock" ]] || { echo "bridge, Flutter app, or source lock prerequisite missing" >&2; exit 65; }
[[ ! -e "$bridge/Cargo.lock" && ! -e "$app/pubspec.lock" ]] || { echo "bootstrap refuses to overwrite an existing approved lockfile" >&2; exit 66; }
mkdir -p "$stage/logs"
src_lock_before="$(sha256 "$source_lock")"
cargo generate-lockfile --manifest-path "$bridge/Cargo.toml" 2>&1 | tee "$stage/logs/bridge-generate-lockfile.log"
[[ -f "$bridge/Cargo.lock" && "$(sha256 "$source_lock")" == "$src_lock_before" ]] || { echo "bridge bootstrap failed or changed SRC/Cargo.lock" >&2; exit 67; }
(
  cd "$app"
  "$FLUTTER_SDK/bin/flutter" pub get 2>&1 | tee "$stage/logs/flutter-pub-get.log"
)
[[ -f "$app/pubspec.lock" && "$(sha256 "$source_lock")" == "$src_lock_before" ]] || { echo "Flutter bootstrap failed or changed SRC/Cargo.lock" >&2; exit 68; }
cp "$bridge/Cargo.lock" "$stage/bridge-Cargo.lock"
cp "$app/pubspec.lock" "$stage/pubspec.lock"
jq -n --arg head "$GITHUB_SHA" --arg src_lock "$src_lock_before" --arg bridge_lock "$(sha256 "$bridge/Cargo.lock")" --arg pub_lock "$(sha256 "$app/pubspec.lock")" --arg cargo "$(sha256 "$bridge/Cargo.toml")" --arg pubspec "$(sha256 "$app/pubspec.yaml")" '{schema:"neoth.mobile-lock-bootstrap.v1",source_head:$head,src_cargo_lock_sha256:$src_lock,bridge_cargo_toml_sha256:$cargo,bridge_cargo_lock_sha256:$bridge_lock,app_pubspec_yaml_sha256:$pubspec,app_pubspec_lock_sha256:$pub_lock,outputs:["bridge-Cargo.lock","pubspec.lock"]}' > "$stage/bootstrap-provenance.json"
