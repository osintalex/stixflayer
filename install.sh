#!/bin/sh
# Install the stixflayer CLI on Linux or macOS.
#
# Usage:
#   curl -LsSf https://github.com/osintalex/stixflayer/releases/latest/download/install.sh | sh
#
# Environment:
#   STIXFLAYER_VERSION      Release version to install (default: latest CLI release)
#   STIXFLAYER_INSTALL_DIR  Directory for the binary (default: ~/.local/bin)
#   STIXFLAYER_REPO         GitHub repository (default: osintalex/stixflayer)
set -eu

REPO="${STIXFLAYER_REPO:-osintalex/stixflayer}"
INSTALL_DIR="${STIXFLAYER_INSTALL_DIR:-$HOME/.local/bin}"

say() {
    printf 'stixflayer install: %s\n' "$*"
}

fail() {
    printf 'stixflayer install: error: %s\n' "$*" >&2
    exit 1
}

detect_os() {
    case "$(uname -s)" in
        Linux) printf 'linux\n' ;;
        Darwin) printf 'darwin\n' ;;
        *) fail "unsupported operating system '$(uname -s)'; supported platforms are Linux and macOS" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) printf 'x86_64\n' ;;
        arm64 | aarch64) printf 'aarch64\n' ;;
        *) fail "unsupported architecture '$(uname -m)'; supported architectures are x86_64 and aarch64" ;;
    esac
}

target_for() {
    case "$1-$2" in
        linux-x86_64) printf 'x86_64-unknown-linux-musl\n' ;;
        linux-aarch64) printf 'aarch64-unknown-linux-musl\n' ;;
        darwin-x86_64) printf 'x86_64-apple-darwin\n' ;;
        darwin-aarch64) printf 'aarch64-apple-darwin\n' ;;
        *) fail "unsupported platform $1-$2; supported platforms are Linux and macOS on x86_64 or aarch64" ;;
    esac
}

download() {
    url="$1"
    destination="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$destination"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$destination" "$url"
    else
        fail "curl or wget is required to download stixflayer"
    fi
}

latest_version() {
    api="https://api.github.com/repos/${REPO}/releases?per_page=30"
    if command -v curl >/dev/null 2>&1; then
        releases="$(curl -fsSL "$api")" || fail "could not query the latest release"
    elif command -v wget >/dev/null 2>&1; then
        releases="$(wget -qO- "$api")" || fail "could not query the latest release"
    else
        fail "curl or wget is required to download stixflayer"
    fi
    version="$(printf '%s\n' "$releases" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"cli-v\([^"]*\)".*/\1/p' \
        | head -n 1)"
    [ -n "$version" ] || fail "no cli-v release was found for ${REPO}; set STIXFLAYER_VERSION to install a specific version"
    printf '%s\n' "$version"
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        fail "sha256sum or shasum is required to verify the download"
    fi
}

os="$(detect_os)"
arch="$(detect_arch)"
target="$(target_for "$os" "$arch")"

version="${STIXFLAYER_VERSION:-}"
if [ -z "$version" ]; then
    version="$(latest_version)"
fi
version="${version#cli-v}"
version="${version#v}"

archive="stixflayer-${version}-${target}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/cli-v${version}"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/stixflayer.XXXXXX")"
cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

say "downloading ${archive}"
download "${base_url}/${archive}" "${tmp_dir}/${archive}"
download "${base_url}/SHA256SUMS" "${tmp_dir}/SHA256SUMS"

expected="$(awk -v name="$archive" '$2 == name {print $1}' "${tmp_dir}/SHA256SUMS" | head -n 1)"
[ -n "$expected" ] || fail "SHA256SUMS does not contain ${archive}"

actual="$(sha256_file "${tmp_dir}/${archive}")"
[ "$expected" = "$actual" ] || fail "checksum mismatch for ${archive}; refusing to install"

tar -xzf "${tmp_dir}/${archive}" -C "$tmp_dir"
[ -f "${tmp_dir}/stixflayer" ] || fail "archive did not contain the stixflayer binary"

mkdir -p "$INSTALL_DIR"
cp "${tmp_dir}/stixflayer" "${INSTALL_DIR}/stixflayer"
chmod 0755 "${INSTALL_DIR}/stixflayer"

say "installed stixflayer ${version} to ${INSTALL_DIR}/stixflayer"
case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *) say "add ${INSTALL_DIR} to PATH to run stixflayer from any shell" ;;
esac
