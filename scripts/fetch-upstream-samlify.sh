#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT}/reference/upstream-samlify/VERSION.md"

default_version() {
	if [[ ! -f "${VERSION_FILE}" ]]; then
		echo "2.10.2"
		return
	fi
	# First backtick-delimited value in the VERSION.md "Version" table row.
	grep -E '^\| Version \|' "${VERSION_FILE}" | sed -n 's/.*`\([^`]*\)`.*/\1/p' | head -n 1
}

VERSION="${1:-$(default_version)}"
DEST="${ROOT}/reference/upstream-samlify/${VERSION}/repository"
REPO_URL="https://github.com/tngan/samlify.git"
TAG="v${VERSION}"

if [[ -d "${DEST}/.git" ]] || [[ -f "${DEST}/package.json" ]]; then
	echo "Upstream tree already exists at ${DEST}"
	echo "Remove that directory to re-clone."
	exit 0
fi

mkdir -p "$(dirname "${DEST}")"
echo "Cloning ${REPO_URL} (${TAG}) into ${DEST} ..."
git clone --depth 1 --branch "${TAG}" "${REPO_URL}" "${DEST}"
echo "Done. samlify sources: ${DEST}"
