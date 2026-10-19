# GNU coreutils on CI, BSD userland on macOS. Shims only when the GNU
# tool is absent, so Linux behavior is unchanged.
if ! command -v sha256sum >/dev/null 2>&1; then
    sha256sum() { shasum -a 256 "$@"; }
fi

if ! command -v setsid >/dev/null 2>&1; then
    # macOS has no setsid. The caller backgrounds the server itself.
    setsid() { "$@"; }
fi

# Byte length: GNU `stat -c%s`, BSD `stat -f%z`.
file_bytes() {
    if stat -c%s "$1" >/dev/null 2>&1; then
        stat -c%s "$1"
    else
        stat -f%z "$1"
    fi
}
