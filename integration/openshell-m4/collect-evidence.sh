#!/bin/bash
# Capture target-native logs for one sandbox. The caller filters the text.
set -u
export PATH="${HOME}/.local/bin:${PATH}"
export DOCKER_CONFIG=/tmp/fip-m4-docker
name="${1:?sandbox name}"
echo "==== containers ===="
docker ps -a --filter "name=${name}" --format '{{.Names}}' || echo "docker-list-failed"
docker ps -aq --filter "name=${name}" | while read -r id; do
  echo "==== docker-logs [redacted] ===="
  docker logs "${id}" 2>&1 || echo "docker-logs-failed"
done
echo "==== gateway-stream ===="
timeout 5 openshell --color never logs "${name}" --source sandbox || true
