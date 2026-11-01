"""生成占位的专家自评数据（data/expert_scores/rater_*.json）。

⚠️ 这是**占位基线**，不是真人评分。
   用途：让 Kendall's W 一致性检验、评分卡覆盖逻辑在拿到真实数据前即可跑通。
   正式实验前必须由三位组员各自独立填写 18 格 × 5 属性的打分并替换本目录下的文件。

三位评分者的取值来自 taxonomy.BASE_ATTRIBUTES + AUTONOMY_BONUS 的基线，
叠加各人固定的分歧偏移（模拟真实评分中常见的松紧差异），使 W 落在中度一致区间。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ethgate.taxonomy import (  # noqa: E402
    BASE_ATTRIBUTES,
    AUTONOMY_BONUS,
    RiskAttributes,
    AHP_WEIGHTS,
)
from ethgate.types import Autonomy, Layer  # noqa: E402

# 各评分者的属性偏好偏移（固定，可复现）。
# 文件名用中性的 rater_a / rater_b / rater_c，避免夹带任何可识别到个人的信息；
# 真实评分时由三位组员各自填写同一结构的文件，仍沿用这三个中性名。
RATERS = {
    "rater_a": {"goal_drift": +1, "impact_radius": 0, "reversibility": 0,
                "observability": 0, "permission_expansion": -1},
    "rater_b": {"goal_drift": 0, "impact_radius": +1, "reversibility": -1,
                "observability": +1, "permission_expansion": 0},
    "rater_c": {"goal_drift": +1, "impact_radius": -1, "reversibility": +1,
                "observability": -1, "permission_expansion": 0},
}


def build(rater: str) -> dict[str, dict[str, int]]:
    off = RATERS[rater]
    out: dict[str, dict[str, int]] = {}
    for layer in Layer:
        for autonomy in Autonomy:
            vals: dict[str, int] = {}
            for f in RiskAttributes.FIELDS:
                base = BASE_ATTRIBUTES[layer][f] + AUTONOMY_BONUS[autonomy][f]
                # 按属性权重微调：权重高的属性，评分者更容易给出极端判断
                spread = 1 if AHP_WEIGHTS.get(f, 0.2) >= 0.22 else 0
                v = base + off[f] + (spread if off[f] > 0 else -spread if off[f] < 0 else 0)
                vals[f] = max(1, min(5, v))
            out[f"{layer.value}×{autonomy.value}"] = vals
    return out


def main() -> None:
    d = ROOT / "data" / "expert_scores"
    d.mkdir(parents=True, exist_ok=True)
    for rater in RATERS:
        p = d / f"{rater}.json"
        p.write_text(
            json.dumps(build(rater), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"写入 {p.relative_to(ROOT)}")

    from ethgate.taxonomy import aggregate_rater_scores

    merged, report = aggregate_rater_scores([build(r) for r in RATERS])
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
