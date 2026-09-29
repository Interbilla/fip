#!/bin/bash
# Environment plumbing for the M4 filesystem slice.
# Starts the pinned OpenShell v0.1.2 gateway. Certificates stay in the user
# state directory and are not repository artifacts. This script is not a FIP
# grant and it does not select filesystem authority.
set -euo pipefail
PKI="${HOME}/.local/state/openshell-fip-m4/pki"
BIND_IP="$(hostname -I | awk '{print $1}')"
STAMP="${PKI}/.bind-ip"
WANT="host.docker.internal ${BIND_IP}"
if [ ! -f "${PKI}/server/tls.crt" ] || [ ! -f "${STAMP}" ] || [ "$(cat "${STAMP}")" != "${WANT}" ]; then
  rm -rf "${PKI}"
  "${HOME}/.local/bin/openshell-gateway" generate-certs \
    --output-dir "${PKI}" \
    --server-san host.docker.internal \
    --server-san "${BIND_IP}" \
    --server-san 127.0.0.1
  printf '%s' "${WANT}" > "${STAMP}"
fi
for name in openshell fip-m4; do
  dir="${HOME}/.config/openshell/gateways/${name}/mtls"
  mkdir -p "${dir}"
  cp "${PKI}/ca.crt" "${dir}/ca.crt"
  cp "${PKI}/client/tls.crt" "${dir}/tls.crt"
  cp "${PKI}/client/tls.key" "${dir}/tls.key"
done
mkdir -p /tmp/fip-m4-docker
printf '%s\n' '{"auths":{}}' > /tmp/fip-m4-docker/config.json
export DOCKER_CONFIG=/tmp/fip-m4-docker
CONFIG="${HOME}/.local/state/openshell-fip-m4/gateway.toml"
cat > "${CONFIG}" <<EOF
[openshell]
version = 2

[openshell.gateway]
bind_address = "0.0.0.0:17670"
compute_driver = "docker"
guest_tls_ca = "${PKI}/ca.crt"
guest_tls_cert = "${PKI}/client/tls.crt"
guest_tls_key = "${PKI}/client/tls.key"

[openshell.gateway.gateway_jwt]
signing_key_path = "${PKI}/jwt/signing.pem"
public_key_path = "${PKI}/jwt/public.pem"
kid_path = "${PKI}/jwt/kid"
gateway_id = "fip-m4"

[openshell.drivers.docker]
socket_path = "/var/run/docker.sock"
image_pull_policy = "if_not_present"
grpc_endpoint = "https://host.docker.internal:17670"
EOF
exec "${HOME}/.local/bin/openshell-gateway" \
  --config "${CONFIG}" \
  --compute-driver docker \
  --tls-cert "${PKI}/server/tls.crt" \
  --tls-key "${PKI}/server/tls.key" \
  --tls-client-ca "${PKI}/ca.crt" \
  --enable-mtls-auth true \
  --log-level info
