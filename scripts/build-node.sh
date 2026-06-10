#!/usr/bin/env bash
# Build the encryption Node.js (CommonJS) WASM package into pkg-node/.
# The package sources (lib/, test/, package.json, .gitignore, ...) are committed in the
# pkg-node submodule; this regenerates the wasm runtime and syncs only the package version.
set -euo pipefail

cd "$(dirname "$0")/.."

# wasm-pack overwrites package.json and .gitignore (and chokes reading the committed
# package.json's nested fields), so set them aside and restore them afterwards.
saved=$(mktemp -d)
cp pkg-node/package.json "$saved/"
cp pkg-node/.gitignore "$saved/"
rm -f pkg-node/package.json

wasm-pack build --release --target nodejs --scope zone-eu --out-dir pkg-node --out-name smime_wasm \
  -- --no-default-features --features "encrypt,console_error_panic_hook"

# Keep the package root clean: the wasm runtime lives under lib/ alongside the shim.
mv pkg-node/smime_wasm.js pkg-node/smime_wasm_bg.wasm \
   pkg-node/smime_wasm.d.ts pkg-node/smime_wasm_bg.wasm.d.ts pkg-node/lib/

# Restore the committed files, syncing the Cargo version (from wasm-pack's output) into package.json.
version=$(node -p "require('./pkg-node/package.json').version")
node -e '
  const fs = require("fs");
  const pkg = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  pkg.version = process.argv[2];
  fs.writeFileSync("pkg-node/package.json", JSON.stringify(pkg, null, 2) + "\n");
' "$saved/package.json" "$version"
cp "$saved/.gitignore" pkg-node/.gitignore
rm -rf "$saved"

# Drop wasm-pack scaffolding.
rm -f pkg-node/README.md pkg-node/index.js pkg-node/index.d.ts

echo "Built pkg-node/ (@zone-eu/smime-js $version)"
