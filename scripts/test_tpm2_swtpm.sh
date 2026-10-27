#!/usr/bin/env bash
# Two swtpm instances. A key sealed on A must unseal on A and fail on B.
# On a host without swtpm (the macOS laptop), re-exec inside ubuntu:24.04.
set -euo pipefail

if [[ "${1:-}" != "--inside" ]] && ! { command -v swtpm >/dev/null && command -v tpm2_createprimary >/dev/null && command -v cargo >/dev/null; }; then
  if command -v docker >/dev/null; then
    exec docker run --rm \
      -v "$PWD":/src -w /src \
      -e CARGO_TARGET_DIR=/tmp/erebus-target \
      ubuntu:24.04 bash /src/scripts/test_tpm2_swtpm.sh --inside
  fi
  echo "need swtpm, tpm2-tools and cargo, or docker" >&2
  exit 1
fi

if [[ "${1:-}" == "--inside" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    swtpm swtpm-tools tpm2-tools ca-certificates curl pkg-config libssl-dev build-essential
  # Cargo.lock v4 needs a current cargo. Ubuntu 24.04 ships 1.75, which cannot read it.
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

root=$(mktemp -d)
cleanup() {
  if [[ -f "$root/a/swtpm.pid" ]]; then kill "$(cat "$root/a/swtpm.pid")" 2>/dev/null || true; fi
  if [[ -f "$root/b/swtpm.pid" ]]; then kill "$(cat "$root/b/swtpm.pid")" 2>/dev/null || true; fi
  rm -rf "$root"
}
trap cleanup EXIT

# The distro CA statedir (/var/lib/swtpm-localca) is not writable by the CI
# runner. Point swtpm-localca at a directory under the temp root instead.
prepare_local_ca() {
  local ca=$1 tool=""
  mkdir -p "$ca"
  if [[ -f /etc/swtpm_setup.conf ]]; then
    tool=$(sed -n 's/^create_certs_tool[[:space:]]*=[[:space:]]*//p' /etc/swtpm_setup.conf | head -1)
  fi
  if [[ -z "$tool" ]]; then
    tool=$(command -v swtpm_localca || true)
  fi
  if [[ -z "$tool" && -x /usr/share/swtpm/swtpm-localca ]]; then
    tool=/usr/share/swtpm/swtpm-localca
  fi
  if [[ -z "$tool" ]]; then
    echo "swtpm_localca not found" >&2
    exit 1
  fi
  if [[ -f /etc/swtpm-localca.options ]]; then
    cp /etc/swtpm-localca.options "$ca/swtpm-localca.options"
  else
    printf '%s\n' "--platform-manufacturer Fedora" "--platform-version 2.1" \
      "--platform-model QEMU" > "$ca/swtpm-localca.options"
  fi
  cat > "$ca/swtpm-localca.conf" <<EOF
statedir = ${ca}
signingkey = ${ca}/signkey.pem
issuercert = ${ca}/issuercert.pem
certserial = ${ca}/certserial
EOF
  cat > "$ca/swtpm_setup.conf" <<EOF
create_certs_tool = ${tool}
create_certs_tool_config = ${ca}/swtpm-localca.conf
create_certs_tool_options = ${ca}/swtpm-localca.options
EOF
}

start_tpm() {
  local dir=$1 port=$2 ctrl=$3
  mkdir -p "$dir"
  swtpm_setup --tpm2 --tpmstate "$dir" --create-ek-cert --create-platform-cert \
    --overwrite --pcr-banks sha256 --config "$root/localca/swtpm_setup.conf"
  swtpm socket --tpm2 \
    --server "type=tcp,port=${port},bindaddr=127.0.0.1" \
    --ctrl "type=tcp,port=${ctrl},bindaddr=127.0.0.1" \
    --tpmstate "dir=${dir}" \
    --flags startup-clear \
    --pid "file=${dir}/swtpm.pid" \
    --daemon
}

prepare_local_ca "$root/localca"
start_tpm "$root/a" 2321 2322
start_tpm "$root/b" 2331 2332
sleep 0.5

export ERE_SWTPM_TEST=1
export ERE_TPM_TCTI_A="swtpm:host=127.0.0.1,port=2321"
export ERE_TPM_TCTI_B="swtpm:host=127.0.0.1,port=2331"
cargo test -p erebus-core --lib swtpm_copied_blob_cannot_unseal -- --nocapture
