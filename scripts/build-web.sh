#!/usr/bin/env bash
# Build the verify-only browser (ESM/bundler) WASM package into pkg/.
# package.json / .gitignore are committed in the pkg submodule; this regenerates the
# wasm output and syncs only the package version.
set -euo pipefail

cd "$(dirname "$0")/.."

# wasm-pack overwrites package.json and .gitignore, so set them aside and restore them.
saved=$(mktemp -d)
cp pkg/package.json "$saved/"
cp pkg/.gitignore "$saved/"
rm -f pkg/package.json

wasm-pack build --release --scope zone-eu --out-dir pkg \
  -- --no-default-features --features "console_error_panic_hook"

cp -r src/locales pkg/

# Restore the committed files, syncing the Cargo version (from wasm-pack's output) into package.json.
version=$(node -p "require('./pkg/package.json').version")
node -e '
  const fs = require("fs");
  const pkg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  pkg.version = process.argv[2];
  fs.writeFileSync("pkg/package.json", JSON.stringify(pkg, null, 2) + "\n");
' "$saved/package.json" "$version"
cp "$saved/.gitignore" pkg/.gitignore
rm -rf "$saved"

rm -f pkg/README.md

echo "Built pkg/ (@zone-eu/smime $version)"
