#!/usr/bin/env bash
# Runs the tunnel benchmark on the current kubectl context, in its own
# `tunnel-bench` namespace, which is deleted afterwards (KEEP=1 keeps it).
#
#   bench/k8s/run.sh [load args...]
#   bench/k8s/run.sh --connections 1000,5000,10000 --delay-ms 1000
#
# MAX_CONCURRENT and MAX_CONNECTIONS set the client's --max-concurrent
# (default 1024) and --max-connections (default 1).
set -euo pipefail

cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
NS=tunnel-bench
OUT=$ROOT/target/bench-linux
MAX_CONCURRENT=${MAX_CONCURRENT:-1024}
MAX_CONNECTIONS=${MAX_CONNECTIONS:-1}
KEEP=${KEEP:-0}

echo "context: $(kubectl config current-context)"

echo "building linux/amd64 binaries"
docker buildx build --quiet -f Dockerfile --output "type=local,dest=$OUT" "$ROOT" >/dev/null

echo "generating keys"
KEYS=$(mktemp -d)
cleanup_keys() { rm -rf "$KEYS"; }
trap cleanup_keys EXIT
(cd "$KEYS" && cargo run -q --release --manifest-path "$ROOT/Cargo.toml" -p tunnel-server -- --print-fingerprint | tail -n1 >server.pin)
(cd "$KEYS" && cargo run -q --release --manifest-path "$ROOT/Cargo.toml" -p tunnel-client -- --print-fingerprint | tail -n1 >client.pin)

cleanup() {
    cleanup_keys
    if [ "$KEEP" = 1 ]; then
        echo "keeping namespace $NS (kubectl delete namespace $NS to remove)"
    else
        echo "deleting namespace $NS"
        kubectl delete namespace "$NS" --wait=false >/dev/null
    fi
}
trap cleanup EXIT

# Start fresh: running pods would keep the pins of a previous run.
kubectl delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
kubectl create namespace "$NS" >/dev/null
kubectl -n "$NS" create secret generic tunnel-bench-keys --from-file="$KEYS" >/dev/null
sed -e "s/__MAX_CONCURRENT__/$MAX_CONCURRENT/" -e "s/__MAX_CONNECTIONS__/$MAX_CONNECTIONS/" bench.yaml | kubectl apply -f - >/dev/null

PODS=(server client destination load)
echo "waiting for pods"
kubectl -n "$NS" wait --for=condition=Ready --timeout=300s "${PODS[@]/#/pod/}" >/dev/null
for pod in "${PODS[@]}"; do
    echo "copying binaries to $pod"
    kubectl -n "$NS" cp "$OUT/." "$pod:/opt/bench/"
    kubectl -n "$NS" exec "$pod" -- touch /opt/bench/ready
done
kubectl -n "$NS" get pods -o wide

# The client logs nothing at warn when it connects, so wait for a request to
# make it through the tunnel instead.
echo "waiting for tunnel"
for _ in $(seq 60); do
    if kubectl -n "$NS" exec load -- /opt/bench/tunnel-bench load --target server:8080 \
        --connections 1 --duration 1 --delay-ms 0 --pause 0 --timeout 2 2>/dev/null |
        awk 'NR==3 && $3 > 0 {ok=1} END {exit !ok}'; then
        break
    fi
    sleep 2
done

echo "client --max-concurrent $MAX_CONCURRENT --max-connections $MAX_CONNECTIONS"
# Sample pod usage during the run; metrics-server reports a ~15s window.
SAMPLES=$KEYS/top
(while sleep 10; do kubectl -n "$NS" top pods --no-headers 2>/dev/null; done) >"$SAMPLES" &
SAMPLER=$!
# Exec gets the soft open-file limit of 1024; raise it like the pods do.
kubectl -n "$NS" exec load -- sh -c 'ulimit -n "$(ulimit -Hn)"; exec "$@"' sh \
    /opt/bench/tunnel-bench load --target server:8080 "$@"
kill "$SAMPLER" 2>/dev/null || true

echo
echo "peak usage during run (limit 2 CPU / 2Gi per pod):"
awk '{cpu=$2+0; mem=$3+0; if (cpu>c[$1]) c[$1]=cpu; if (mem>m[$1]) m[$1]=mem}
     END {for (p in c) printf "  %-12s %6dm CPU %6dMi\n", p, c[p], m[p]}' "$SAMPLES" | sort
for pod in server client; do
    echo "--- $pod log (last 5)"
    kubectl -n "$NS" logs "$pod" --tail=5
done
echo "--- extra connections opened: $(kubectl -n "$NS" logs client | grep -c "opened extra connection" || true)"
