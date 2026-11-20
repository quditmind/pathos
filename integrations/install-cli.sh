#!/bin/sh
# Installs the PATHOS CLI ("pathos") from a GitHub release and verifies it
# against the release's sha256 checksums (and, when cosign is installed,
# the keyless signature of the checksum file).
#
#   PATHOS_CLI_VERSION   release version, e.g. 3.0.0 (required)
#   PATHOS_CLI_REPO      GitHub repository of the release (default quditmind/pathos)
#   PATHOS_CLI_DIR       install directory (default ./.pathos-cli)
#
# Prints the path of the installed binary on the last line.
set -eu

version="${PATHOS_CLI_VERSION:?set PATHOS_CLI_VERSION, e.g. 3.0.0}"
version="${version#v}"
repo="${PATHOS_CLI_REPO:-quditmind/pathos}"
dir="${PATHOS_CLI_DIR:-./.pathos-cli}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  MINGW* | MSYS* | CYGWIN*) os=windows ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
ext=""
[ "$os" = windows ] && ext=".exe"
asset="pathos_${version}_${os}_${arch}${ext}"
base="https://github.com/${repo}/releases/download/v${version}"

mkdir -p "$dir"
cd "$dir"
curl -fsSL --proto '=https' --tlsv1.2 -o "$asset" "$base/$asset"
curl -fsSL --proto '=https' --tlsv1.2 -o checksums.txt "$base/checksums.txt"

expected="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' checksums.txt)"
if [ -z "$expected" ]; then
  echo "no checksum for $asset in checksums.txt" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$asset" | awk '{ print $1 }')"
else
  actual="$(shasum -a 256 "$asset" | awk '{ print $1 }')"
fi
if [ "$expected" != "$actual" ]; then
  echo "checksum mismatch for $asset" >&2
  exit 1
fi

if command -v cosign >/dev/null 2>&1; then
  curl -fsSL --proto '=https' --tlsv1.2 -o checksums.txt.sigstore.json "$base/checksums.txt.sigstore.json"
  cosign verify-blob checksums.txt \
    --bundle checksums.txt.sigstore.json \
    --certificate-identity "https://github.com/${repo}/.github/workflows/release.yml@refs/tags/v${version}" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com >&2
fi

mv "$asset" "pathos${ext}"
chmod +x "pathos${ext}"
echo "PATHOS CLI ${version} (${os}/${arch}) verified" >&2
echo "$(pwd)/pathos${ext}"
