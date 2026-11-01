"""从公开基准导入任务，为题池提供外部依据（一次性运行，产物随库分发）。

来源与协议
----------
GSM8K (OpenAI, MIT License)
    https://github.com/openai/grade-school-math
    小学数学应用题，答案为整数、判分确定。test 集 1319 题。
    本脚本确定性抽样 10 题（seed=2026）转成题池格式，
    每题带 source="gsm8k" 与原题 id。

用法：python tools/import_benchmarks.py
产物：data/sources/gsm8k_tasks.json —— 由 ethgate.minievol 在导入时合并进题池。
"""
from __future__ import annotations

import json
import random
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "sources" / "gsm8k_tasks.json"

GSM8K_URL = (
    "https://raw.githubusercontent.com/openai/grade-school-math/"
    "master/grade_school_math/data/test.jsonl"
)
SEED = 2026
N_PICK = 10


def fetch() -> list[dict]:
    print(f"下载 {GSM8K_URL} ...")
    req = urllib.request.Request(GSM8K_URL, headers={"User-Agent": "ethgate-bench/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8")
    items = [json.loads(line) for line in raw.splitlines() if line.strip()]
    print(f"  共 {len(items)} 题")
    return items


def convert(items: list[dict]) -> list[dict]:
    picked = []
    for it in items:
        gold = it["answer"].rsplit("####", 1)[-1].strip().replace(",", "")
        if not re.fullmatch(r"-?\d+", gold):
            continue  # 只收整数答案，保证确定性判分
        question = re.sub(r"<<[^>]*>>", "", it["question"]).strip()
        picked.append({
            "id": f"bench_{it['id']}" if "id" in it else f"gsm8k_{len(picked)}",
            "source": "gsm8k",
            "source_id": it.get("id", ""),
            "kind": "基准数学",
            "question": question,
            "answer": gold,
        })
    return picked


def main() -> int:
    items = fetch()
    pool = convert(items)
    rng = random.Random(SEED)
    picked = rng.sample(pool, min(N_PICK, len(pool)))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "license": "MIT (github.com/openai/grade-school-math)",
                "imported_at": __import__("time").strftime("%Y-%m-%d"),
                "seed": SEED,
                "tasks": picked,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"已写入 {OUT.relative_to(ROOT)}（{len(picked)} 题，seed={SEED}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
