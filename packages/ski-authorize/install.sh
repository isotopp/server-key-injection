#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    printf '%s\n' 'ski-authorize install.sh must run as root' >&2
    exit 1
fi

readonly INSTALL_ROOT="/opt/ski-authorize"
readonly CONFIG_DIR="${INSTALL_ROOT}/config"
readonly POLICY_PATH="/opt/ski-authorize/config/authorization.toml"
readonly SSHD_FRAGMENT_PATH="/etc/ssh/sshd_config.d/60-ski-authorize.conf"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly AUTHZ_USER="ski-authz"
readonly AUTHZ_GROUP="ski-authz"

export UV_PYTHON_INSTALL_DIR="/opt/ski-authorize/python"
export UV_TOOL_DIR="/opt/ski-authorize/tools"
export UV_TOOL_BIN_DIR="/opt/ski-authorize/bin"
export UV_CACHE_DIR="/opt/ski-authorize/cache"

die() {
    printf 'ski-authorize: %s\n' "$1" >&2
    exit 1
}

command -v uv >/dev/null 2>&1 || die "uv is required"
command -v getent >/dev/null 2>&1 || die "getent is required"
command -v useradd >/dev/null 2>&1 || die "useradd is required"

if ! getent passwd "${AUTHZ_USER}" >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "${AUTHZ_USER}"
fi

install -d -o root -g root -m 0755 "${INSTALL_ROOT}"
install -d -o root -g root -m 0755 "${UV_PYTHON_INSTALL_DIR}"
install -d -o root -g root -m 0755 "${UV_TOOL_DIR}"
install -d -o root -g root -m 0755 "${UV_TOOL_BIN_DIR}"
install -d -o root -g root -m 0700 "${UV_CACHE_DIR}"
install -d -o root -g "${AUTHZ_GROUP}" -m 0750 "${CONFIG_DIR}"
install -d -o root -g root -m 0755 /etc/ssh/sshd_config.d

uv python install 3.12
uv tool install --python 3.12 --managed-python --upgrade "${SCRIPT_DIR}"

validate_directory() {
    local path="$1"
    local owner mode

    [[ -d "${path}" && ! -L "${path}" ]] || die "unsafe directory: ${path}"
    owner=$(stat -c %u "${path}")
    mode=$(stat -c %a "${path}")
    [[ "${owner}" == 0 ]] || die "directory is not root-owned: ${path}"
    (( (8#${mode} & 022) == 0 )) || die "directory is group/world writable: ${path}"
}

validate_file() {
    local path="$1"
    local owner mode

    [[ -f "${path}" && ! -L "${path}" ]] || die "unsafe file: ${path}"
    owner=$(stat -c %u "${path}")
    mode=$(stat -c %a "${path}")
    [[ "${owner}" == 0 ]] || die "file is not root-owned: ${path}"
    (( (8#${mode} & 022) == 0 )) || die "file is group/world writable: ${path}"
}

install_if_absent() {
    local source="$1"
    local destination="$2"
    local group="$3"
    local mode="$4"

    if [[ -e "${destination}" || -L "${destination}" ]]; then
        validate_file "${destination}"
        return
    fi
    install -o root -g "${group}" -m "${mode}" "${source}" "${destination}"
}

install_if_absent \
    "${SCRIPT_DIR}/src/ski_authorize/examples/authorization.toml" \
    "${POLICY_PATH}" \
    "${AUTHZ_GROUP}" \
    0640
install_if_absent \
    "${SCRIPT_DIR}/src/ski_authorize/examples/60-ski-authorize.conf" \
    "${SSHD_FRAGMENT_PATH}" \
    root \
    0644

for path in \
    "${INSTALL_ROOT}" \
    "${UV_PYTHON_INSTALL_DIR}" \
    "${UV_TOOL_DIR}" \
    "${UV_TOOL_BIN_DIR}" \
    "${UV_CACHE_DIR}" \
    "${CONFIG_DIR}"; do
    validate_directory "${path}"
done

validate_file "${POLICY_PATH}"
validate_file "${SSHD_FRAGMENT_PATH}"
[[ -x "${UV_TOOL_BIN_DIR}/ski-authorize" ]] || die "ski-authorize command was not installed"

printf '%s\n' "ski-authorize installed below ${INSTALL_ROOT}"
