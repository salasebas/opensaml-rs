#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT}/reference/upstream-samlify/VERSION.md"

default_version() {
	if [[ ! -f "${VERSION_FILE}" ]]; then
		echo "2.13.1"
		return
	fi
	# First backtick-delimited value in the VERSION.md "Version" table row.
	grep -E '^\| Version \|' "${VERSION_FILE}" | sed -n 's/.*`\([^`]*\)`.*/\1/p' | head -n 1
}

default_commit() {
	if [[ ! -f "${VERSION_FILE}" ]]; then
		echo ""
		return
	fi
	grep -E '^\| Commit \|' "${VERSION_FILE}" | sed -n 's/.*`\([^`]*\)`.*/\1/p' | head -n 1
}

DEFAULT_VERSION="$(default_version)"
VERSION="${1:-${DEFAULT_VERSION}}"
if [[ -z "${PINNED_COMMIT+x}" ]]; then
	if [[ "${VERSION}" == "${DEFAULT_VERSION}" ]]; then
		PINNED_COMMIT="$(default_commit)"
	else
		PINNED_COMMIT=""
	fi
fi
DEST="${ROOT}/reference/upstream-samlify/${VERSION}/repository"
REPO_URL="https://github.com/tngan/samlify.git"
TAG="v${VERSION}"

verify_pinned_commit() {
	if [[ -z "${PINNED_COMMIT}" ]]; then
		return
	fi
	actual="$(git -C "${DEST}" rev-parse HEAD)"
	if [[ "${actual}" != "${PINNED_COMMIT}" ]]; then
		echo "Pinned commit mismatch for ${TAG}:"
		echo "  expected ${PINNED_COMMIT}"
		echo "  actual   ${actual}"
		exit 1
	fi
}

if [[ -d "${DEST}/.git" ]] || [[ -f "${DEST}/package.json" ]]; then
	echo "Upstream tree already exists at ${DEST}"
	if [[ -d "${DEST}/.git" ]]; then
		verify_pinned_commit
		if [[ -n "${PINNED_COMMIT}" ]]; then
			echo "Pinned commit verified."
		fi
	fi
	exit 0
fi

mkdir -p "$(dirname "${DEST}")"
echo "Cloning ${REPO_URL} (${TAG}) into ${DEST} ..."
git clone --depth 1 --branch "${TAG}" "${REPO_URL}" "${DEST}"
verify_pinned_commit
echo "Done. samlify sources: ${DEST}"
