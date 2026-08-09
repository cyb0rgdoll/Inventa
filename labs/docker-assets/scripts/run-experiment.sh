#!/usr/bin/env sh
set -eu

LAB_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO_DIR="$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT_ROOT="$REPO_DIR/results/docker-mixed-methods-$STAMP"
CONTAINER_OUT_ROOT="/workspace/results/docker-mixed-methods-$STAMP"

mkdir -p "$OUT_ROOT"
cp "$LAB_DIR/ground_truth.csv" "$OUT_ROOT/manual_baseline_inventory.csv"

cd "$LAB_DIR"
docker compose up -d --build

echo "Waiting for lab services to settle..."
sleep "${INVENTA_LAB_WAIT_SECONDS:-20}"

run_config() {
  config="$1"
  run_no="$2"
  shift 2
  run_dir="$OUT_ROOT/$config/run_$run_no"
  container_run_dir="$CONTAINER_OUT_ROOT/$config/run_$run_no"
  mkdir -p "$run_dir"
  echo "==> $config run $run_no"
  docker compose run --rm scanner "$@" -o "$container_run_dir" > "$run_dir/console.log" 2>&1
  cat "$run_dir/console.log"
}

for run_no in 1 2 3; do
  run_config quick "$run_no" \
    -s labs/docker-assets/scope.txt \
    -t labs/docker-assets/targets.txt \
    -W quick \
    --report both
done

for run_no in 1 2 3; do
  run_config standard "$run_no" \
    -s labs/docker-assets/scope.txt \
    -t labs/docker-assets/targets.txt \
    -w labs/docker-assets/websites.txt \
    -W standard \
    --report both
done

for run_no in 1 2 3; do
  run_config hybrid_localstack "$run_no" \
    -s labs/docker-assets/scope.txt \
    -t labs/docker-assets/targets.txt \
    -w labs/docker-assets/websites.txt \
    -W standard \
    --cloud-enum \
    --cloud-provider aws \
    --report both
done

cd "$REPO_DIR"
python3 labs/docker-assets/scripts/summarise_experiment.py "$OUT_ROOT" "$OUT_ROOT/manual_baseline_inventory.csv"

echo
echo "Experiment output: $OUT_ROOT"
echo "Summary: $OUT_ROOT/evaluation_summary.csv"
