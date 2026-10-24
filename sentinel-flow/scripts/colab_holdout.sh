#!/usr/bin/env bash
# Re-run only the holdout evaluation after scripts/colab_train.sh, then
# re-package /root/sentinel_model.zip. Usage (Colab cell):
#   !git -C /root/cv_work pull -q
#   !bash /root/cv_work/sentinel-flow/scripts/colab_holdout.sh
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export LD_LIBRARY_PATH=${NDPI_DIR:-/root/nDPI}/src/lib
OUT=/root/sentinel_model.zip
echo "==> holdout evaluation"
python3 "$ROOT/engine-ml/models/evaluate_holdout.py" 2>&1 | tail -14
echo "==> package"
cd "$ROOT/engine-ml/models"
rm -f "$OUT"
zip -q "$OUT" c2_detector.onnx anomaly_iforest.onnx model_meta.json \
    evaluation.json evaluation_holdout.json
ls -la "$OUT"
