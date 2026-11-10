#!/usr/bin/env bash
# Creates the kind cluster (once), builds and loads the image, applies the
# manifests and waits for every deployment. Then run ./bin/demo.
#   SEED=1     also write three past days of SDK logs
#   CHATTER=1  make the fake agent log on its own
set -euo pipefail
cd "$(dirname "$0")"
CLUSTER=sealed
CTX=kind-$CLUSTER
k() { kubectl --context "$CTX" -n sealed-logs "$@"; }

# Preflight: fail now with a clear message rather than halfway through.
fail() { echo "up.sh: $*" >&2; exit 1; }
for tool in docker kind kubectl go; do
  command -v "$tool" >/dev/null || fail "$tool is not installed (needs docker, kind, kubectl, go)"
done
docker info >/dev/null 2>&1 || fail "docker is not running"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  for port in 7101 7102 7103 7104 18123 19100; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      fail "port $port is in use; the cluster maps it to the host (see deploy/kind.yaml)"
    fi
  done
fi

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  prev=$(kubectl config current-context 2>/dev/null || true)
  kind create cluster --config deploy/kind.yaml
  # kind switches the current context; put it back. Everything here uses --context.
  [[ -n $prev ]] && kubectl config use-context "$prev" >/dev/null
fi
docker build -q -t sealedlogs:dev . >/dev/null
kind load docker-image sealedlogs:dev --name "$CLUSTER" >/dev/null
kubectl --context "$CTX" apply -k deploy >/dev/null

# Same tag, new image: restart the app deployments so they pick it up.
k rollout restart deploy/keysvc deploy/collector deploy/aggregator deploy/agent >/dev/null
k set env deploy/agent -c agent AGENT_CHATTER="$([[ ${CHATTER:-0} == 1 ]] && echo 1 || true)" >/dev/null
for d in clickhouse objectstore openbao keysvc collector aggregator agent; do
  k rollout status "deploy/$d" --timeout=300s >/dev/null
done

if [[ ${SEED:-0} == 1 ]]; then
  for d in 1 2 3; do k exec deploy/collector -- producer sdk --days-ago "$d" --n 30 >/dev/null; done
fi

mkdir -p bin
go build -o bin/ ./cmd/demo ./cmd/logs
k get pods
echo
echo "up. ./bin/demo and open http://127.0.0.1:7100, ./bin/logs --as member for the CLI, ./down.sh to delete the cluster"
