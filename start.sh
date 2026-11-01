#!/usr/bin/env bash
# ============================================================
#  自进化智能体的伦理熔断机制 · 一键启动（Linux / macOS）
#  用法： ./start.sh            启动（自动准备数据）
#        ./start.sh --no-data  跳过数据生成，快速启动
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

PY=""
for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 &&
       "$c" -c 'import sys; sys.exit(0 if sys.version_info>=(3,11) else 1)' >/dev/null 2>&1; then
        PY="$c"; break
    fi
done

if [ -z "$PY" ]; then
    echo "[FAIL] 没有找到 Python 3.11+，请先安装。" >&2
    exit 1
fi

echo "使用解释器：$PY"
exec "$PY" tools/start.py --with-data "$@"
