"""系统自检：验证核心模块的数学与逻辑正确性。

运行：python tools/selfcheck.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ethgate.taxonomy import (  # noqa: E402
    ahp_consistency,
    build_matrix,
    load_rater_scores,
    matrix_to_rows,
)


def main() -> int:
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
    audit_ok = check_audit()
    runtime_ok = check_runtime_boundaries()
    ok = bool(ahp["passed"]) and len(cells) == 18 and live_ok and audit_ok and runtime_ok
    print()
    print("自检" + ("全部通过" if ok else "存在失败项"))
    return 0 if ok else 1


def check_live() -> bool:
    """直播主线自检：跑一场 3 代离线进化，验证事件流与熔断判定。"""
    from ethgate.minievol import EvolutionSession, SessionOptions

    print()
    print("=" * 62)
    print("进化直播主线（离线冒烟）")
    print("=" * 62)
    events: list[dict] = []
    from ethgate.config import GateConfig

    # 自检产生的数据放在临时目录，不污染演示会话与正式审计链。
    with tempfile.TemporaryDirectory() as td:
        cfg = GateConfig.load()
        cfg.audit_log = str(Path(td) / "audit.jsonl")
        cfg.state_path = str(Path(td) / "state.json")
        cfg.data_dir = td
        with patch("ethgate.minievol.GateConfig.load", return_value=cfg):
            EvolutionSession(
                SessionOptions(mode="offline", generations=3, speed=500), events.append
            ).run()
        from ethgate.audit import AuditChain
        chain = AuditChain(cfg.audit_log)
        audit_ok = (chain.verify()["valid"]
                    and len(chain.records("verdict")) == 2
                    and len(chain.records("breaker")) == 1)
    types = [e["type"] for e in events]
    ok = (
        bool(types) and types[0] == "session_start"
        and types[-1] == "session_end"
        and any(t == "blocked" for t in types)
        and any(t == "applied" for t in types)
        and audit_ok
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


def check_audit() -> bool:
    """验证损坏记录不能放行、多个实例追加不能丢失缓存记录。"""
    from ethgate.audit import AuditChain

    print("\n审计链回归检查")
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "audit.jsonl"
        first, second = AuditChain(path), AuditChain(path)
        first.append("propose", {"check": 1})
        second.append("verdict", {"check": 2})
        ok = second.verify()["valid"] and len(second.records()) == 2
        with path.open("a", encoding="utf-8") as f:
            f.write("{BROKEN_JSON\n")
        ok = ok and not first.verify()["valid"]
        try:
            first.append("propose", {})
            ok = False
        except ValueError:
            pass
    print(f"  跨实例追加、损坏检测与拒绝追加：{'通过' if ok else '失败'}")
    return ok


def check_runtime_boundaries() -> bool:
    """无网络检查：Φ 传递、提示替换，以及停止后的提交与请求抑制。"""
    from ethgate.minievol import EvolutionSession, SessionOptions, build_modification

    print("\n运行时边界回归检查")
    session = EvolutionSession(SessionOptions(mode="offline"), lambda event: None)
    old = session._vitals.prompts[0]
    new = "先给出精炼结论。"
    mod, note = build_modification(
        1, {"kind": "edit_prompt", "op": "replace", "old": old, "text": new},
        session._vitals, source="selfcheck",
    )
    ok = session._apply(mod, note) and new in session._vitals.prompts and old not in session._vitals.prompts
    calls = []

    class FakeLLM:
        def chat(self, messages, **kwargs):
            calls.append(messages)
            return "1", 0

    session._mode, session._llm = "live", FakeLLM()
    task = {"prompt": "输出 1", "check": lambda answer: (answer == "1", "自检")}
    session._solve_one(task)
    ok = ok and bool(calls) and all(c in calls[0][0]["content"] for c in session._vitals.constraints)
    session.stop_flag = True
    before = session._vitals.clone()
    ok = ok and not session._apply(mod, note) and session._vitals == before
    session._solve_one(task)
    proposal, _ = session._make_proposal(2)
    ok = ok and len(calls) == 1 and proposal is None
    print(f"  Φ 传递、提示替换与停止检查：{'通过' if ok else '失败'}")
    return bool(ok)


if __name__ == "__main__":
    sys.exit(main())
