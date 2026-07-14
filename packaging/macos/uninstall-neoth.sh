#!/bin/sh
set -eu

app=/Applications/NEOTH.app
identifier=io.github.the-geek-freaks.neoth

if [ "$(id -u)" -ne 0 ]; then
  exec sudo "$0" "$@"
fi

for name in neoth neothd neothd-gui neoth-migrate neoth-relay neoth-keet-bridge; do
  link="/usr/local/bin/$name"
  expected="$app/Contents/MacOS/$name"
  if [ -L "$link" ] && [ "$(readlink "$link")" = "$expected" ]; then
    rm -f "$link"
  fi
done

uninstall_link=/usr/local/bin/neoth-uninstall
if [ -L "$uninstall_link" ] && [ "$(readlink "$uninstall_link")" = "$app/Contents/Resources/uninstall-neoth.sh" ]; then
  rm -f "$uninstall_link"
fi

if [ -d "$app" ]; then
  actual_identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist" 2>/dev/null || true)
  [ "$actual_identifier" = "$identifier" ] || {
    printf 'error: refusing to remove %s: bundle identifier is not %s\n' "$app" "$identifier" >&2
    exit 1
  }
  rm -rf "$app"
fi

pkgutil --forget "$identifier" >/dev/null 2>&1 || true
printf 'NEOTH application files removed; personal data was preserved.\n'
