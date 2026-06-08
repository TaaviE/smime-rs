#!/usr/bin/env bash
set -euo pipefail

#
# diff_upstream.sh - Compare local vendorized pyca/cryptography x509 crates
#                    against the current upstream main branch.
#
# Usage:  ./scripts/diff_upstream.sh [output_file]
# Output: pkg/diff_summary.txt (default) or the path given as $1
#

# Configuration
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_FILE="${1:-${PROJECT_ROOT}/pkg/diff_summary.txt}"
UPSTREAM_REPO="https://github.com/pyca/cryptography.git"
CLONE_DIR="${PROJECT_ROOT}/tmp/upstream-cryptography"

# Upstream base paths (inside clone)
UPSTREAM_X509="src/rust/cryptography-x509/src"
UPSTREAM_X509_VERIF="src/rust/cryptography-x509-verification/src"

# Local base paths
LOCAL_X509="${PROJECT_ROOT}/vendor/pyca-cryptography/cryptography-x509"
LOCAL_X509_VERIF="${PROJECT_ROOT}/vendor/pyca-cryptography/cryptography-x509-verification"

# Phase 1: get upstream source
echo "Fetching upstream pyca/cryptography (shallow clone)..."

if [ -d "${CLONE_DIR}/.git" ]; then
    echo "Existing clone found, pulling latest main..."
    git -C "${CLONE_DIR}" fetch --depth=1 origin main
    git -C "${CLONE_DIR}" reset --hard FETCH_HEAD --quiet
else
    echo "Cloning (sparse, depth=1)..."
    mkdir -p "$(dirname "${CLONE_DIR}")"
    git clone \
        --depth=1 \
        --filter=blob:none \
        --sparse \
        "${UPSTREAM_REPO}" \
        "${CLONE_DIR}"
    git -C "${CLONE_DIR}" sparse-checkout set \
        "src/rust/cryptography-x509/src" \
        "src/rust/cryptography-x509-verification/src"
fi

UPSTREAM_COMMIT="$(git -C "${CLONE_DIR}" rev-parse HEAD)"
UPSTREAM_DATE="$(git -C "${CLONE_DIR}" log -1 --format=%ci HEAD)"
echo "Upstream commit: ${UPSTREAM_COMMIT}"
echo "Upstream date:   ${UPSTREAM_DATE}"

# Phase 2: generate diffs
mkdir -p "$(dirname "${OUTPUT_FILE}")"

TOTAL_CHANGED=0
TOTAL_IDENTICAL=0
TOTAL_MISSING_LOCAL=0
TOTAL_MISSING_UPSTREAM=0

{
    echo "Upstream diff summary"
    echo "Generated:       $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Upstream repo:   ${UPSTREAM_REPO}"
    echo "Upstream commit: ${UPSTREAM_COMMIT}"
    echo "Upstream date:   ${UPSTREAM_DATE}"
    echo ""

    diff_file() {
        local local_path="$1"
        local upstream_path="$2"
        local display_local="$3"
        local display_upstream="$4"

        echo "File: ${display_local}"
        echo "  upstream: ${display_upstream}"

        if [ ! -f "${local_path}" ]; then
            echo "  local file missing"
            TOTAL_MISSING_LOCAL=$((TOTAL_MISSING_LOCAL + 1))
            echo ""
            return
        fi
        if [ ! -f "${upstream_path}" ]; then
            echo "  upstream file missing (local-only file)"
            TOTAL_MISSING_UPSTREAM=$((TOTAL_MISSING_UPSTREAM + 1))
            echo ""
            return
        fi

        if diff -u "${upstream_path}" "${local_path}" \
            --label "a/${display_upstream}" \
            --label "b/${display_local}" > /dev/null 2>&1; then
            echo "  identical"
            TOTAL_IDENTICAL=$((TOTAL_IDENTICAL + 1))
        else
            diff -u "${upstream_path}" "${local_path}" \
                --label "a/${display_upstream}" \
                --label "b/${display_local}" || true
            TOTAL_CHANGED=$((TOTAL_CHANGED + 1))
        fi
        echo ""
    }

    # Crate: cryptography-x509
    echo "Crate: cryptography-x509"
    echo ""

    declare -A X509_FILES
    if [ -d "${LOCAL_X509}" ]; then
        while IFS= read -r -d '' f; do
            rel="${f#${LOCAL_X509}/}"
            X509_FILES["${rel}"]=1
        done < <(find "${LOCAL_X509}" -name "*.rs" -print0)
    fi
    if [ -d "${CLONE_DIR}/${UPSTREAM_X509}" ]; then
        while IFS= read -r -d '' f; do
            rel="${f#${CLONE_DIR}/${UPSTREAM_X509}/}"
            X509_FILES["${rel}"]=1
        done < <(find "${CLONE_DIR}/${UPSTREAM_X509}" -name "*.rs" -print0)
    fi

    for file in $(echo "${!X509_FILES[@]}" | tr ' ' '\n' | sort); do
        diff_file \
            "${LOCAL_X509}/${file}" \
            "${CLONE_DIR}/${UPSTREAM_X509}/${file}" \
            "cryptography-x509/${file}" \
            "cryptography-x509/src/${file}"
    done

    # Crate: cryptography-x509-verification
    echo "Crate: cryptography-x509-verification"
    echo ""

    declare -A X509V_FILES
    if [ -d "${LOCAL_X509_VERIF}" ]; then
        while IFS= read -r -d '' f; do
            rel="${f#${LOCAL_X509_VERIF}/}"
            X509V_FILES["${rel}"]=1
        done < <(find "${LOCAL_X509_VERIF}" -name "*.rs" -print0)
    fi
    if [ -d "${CLONE_DIR}/${UPSTREAM_X509_VERIF}" ]; then
        while IFS= read -r -d '' f; do
            rel="${f#${CLONE_DIR}/${UPSTREAM_X509_VERIF}/}"
            X509V_FILES["${rel}"]=1
        done < <(find "${CLONE_DIR}/${UPSTREAM_X509_VERIF}" -name "*.rs" -print0)
    fi

    for file in $(echo "${!X509V_FILES[@]}" | tr ' ' '\n' | sort); do
        diff_file \
            "${LOCAL_X509_VERIF}/${file}" \
            "${CLONE_DIR}/${UPSTREAM_X509_VERIF}/${file}" \
            "cryptography-x509-verification/${file}" \
            "cryptography-x509-verification/src/${file}"
    done

    # Summary
    echo "Summary"
    echo "  Files with differences: ${TOTAL_CHANGED}"
    echo "  Identical files:        ${TOTAL_IDENTICAL}"
    echo "  Missing locally:        ${TOTAL_MISSING_LOCAL}"
    echo "  Missing upstream:       ${TOTAL_MISSING_UPSTREAM}"
    echo "  Total files compared:   $((TOTAL_CHANGED + TOTAL_IDENTICAL + TOTAL_MISSING_LOCAL + TOTAL_MISSING_UPSTREAM))"

} > "${OUTPUT_FILE}"

echo ""
echo "Diff summary written to: ${OUTPUT_FILE}"
echo "  Files with differences:  ${TOTAL_CHANGED}"
echo "  Identical files:         ${TOTAL_IDENTICAL}"
echo "  Missing locally:         ${TOTAL_MISSING_LOCAL}"
echo "  Missing upstream:        ${TOTAL_MISSING_UPSTREAM}"
