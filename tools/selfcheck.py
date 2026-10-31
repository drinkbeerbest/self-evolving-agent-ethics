"""系统自检：验证核心模块的数学与逻辑正确性。

运行：python tools/selfcheck.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ethgate.taxonomy import (  # noqa: E402
    ahp_consistency,
    build_matrix,
    load_rater_scores,
    matrix_to_rows,
)


def main() -> None:
    print("=" * 62)
    print("AHP 一致性检验")
    print("=" * 62)
    ahp = ahp_consistency()
    print(f"  lambda_max = {ahp['lambda_max']}   CI = {ahp['ci']}   CR = {ahp['cr']}")
    print(f"  是否通过 (CR < 0.10): {'通过' if ahp['passed'] else '未通过'}")
    print("  权重:")
    for k, v in ahp["weights"].items():
        print(f"    {k:24s} {v}")

    print()
    print("=" * 62)
    print("专家自评聚合")
    print("=" * 62)
    overrides, report = load_rater_scores(str(ROOT / "data" / "expert_scores"))
    print(json.dumps(report, ensure_ascii=False, indent=2))

    print()
    print("=" * 62)
    print("18 格风险矩阵（风险指数降序）")
    print("=" * 62)
    cells = build_matrix(overrides=overrides or None)
    for c in sorted(cells, key=lambda x: -x.risk_index):
        flag = "  <== 高危" if c.is_high_risk else ""
        attrs = c.attributes.as_dict()
        detail = " ".join(f"{k[:4]}={v}" for k, v in attrs.items())
        print(f"  {c.key:38s} {c.risk_index:5.2f}  {detail}{flag}")

    hi = [c for c in cells if c.is_high_risk]
    print()
    print(f"  高危格共 {len(hi)} 格：")
    for c in hi:
        print(f"    {c.key}  {c.risk_index:.2f}")
    print()
    print("  开题报告的初步判断是「架构层自主采纳、约束层任意自主度、代码层自主采纳」三格高危。")
    print("  本次自评结果与之对比：")
    predicted = {"架构×系统自主采纳·人类事后审计",
                 "约束×系统提议·人类批准",
                 "约束×系统提议·系统初筛·人类抽检",
                 "约束×系统自主采纳·人类事后审计",
                 "代码×系统自主采纳·人类事后审计"}
    got = {c.key for c in hi}
    print(f"    预测命中: {sorted(predicted & got) or '无'}")
    print(f"    新增高危: {sorted(got - predicted) or '无'}")
    print(f"    预测但未达阈值: {sorted(predicted - got) or '无'}")

    live_ok = check_live()
    print()
    print("自检" + ("全部通过" if live_ok else "存在失败项"))


def check_live() -> bool:
    """直播主线自检：跑一场 3 代离线进化，验证事件流与熔断判定。"""
    from ethgate.minievol import EvolutionSession, SessionOptions

    print()
    print("=" * 62)
    print("进化直播主线（离线冒烟）")
    print("=" * 62)
    events: list[dict] = []
    EvolutionSession(
        SessionOptions(mode="offline", generations=3, speed=500), events.append
    ).run()
    types = [e["type"] for e in events]
    ok = (
        types[0] == "session_start"
        and types[-1] == "session_end"
        and any(t == "blocked" for t in types)
        and any(t == "applied" for t in types)
    )
    blocked = [e for e in events if e["type"] == "blocked"]
    applied = [e for e in events if e["type"] == "applied"]
    print(f"  事件 {len(events)} 条 · 拦截 {len(blocked)} · 放行 {len(applied)}")
    for e in blocked:
        print(f"    [拦截] 第 {e['gen']} 代 {e['note']}")
    for e in applied:
        print(f"    [放行] 第 {e['gen']} 代 {e['note']}")
    print(f"  结论: {'通过' if ok else '失败'}")
    return ok


if __name__ == "__main__":
    main()
