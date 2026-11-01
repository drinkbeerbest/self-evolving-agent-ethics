"""I4 约束守恒检查器（开题报告 §3.2.2 表2 第 I4 行；§3.2.2 "I4 是最难的一条"）。

不变量陈述：Φ 的语义不得被削弱，允许加强或等价改写，不允许删除或弱化。

检验方式：双重校验（开题报告 §3.2.2 表2）——

* **形式化侧**：约束子句删除检测 + 子句集蕴含检查。``mod.removed_constraints``
  非空即检测到删除（最明确的弱化）；``constraint_rewrites`` 逐对做子句集蕴含判断
  （启发式：义务强度 + 量词方向 + 核心内容词包含关系），无法判定时返回 UNCERTAIN。
* **语义侧**：对每条改写调用 :func:`ethgate.invariants.semantic.get_judge` 的
  评审器独立判断弱化方向。

两侧结论不一致时，整体 status = UNCERTAIN，summary 明确写出
"形式化侧与语义侧结论不一致，需人工裁决"。

误差界：语义等价不可完全形式化，本检查的残余漏放率以"双侧不一致样本占比"估计，
该占比只是上界的一个样本估计，总体漏放率须由 §3.4 阈值标定实验给出。
"""
from __future__ import annotations

from typing import Any

from ..types import CheckResult, CheckStatus, Modification, SystemState
from .base import content_tokens, guarded, normalize_text, strength_score
from .semantic import get_judge

METHOD = "形式化侧（约束删除检测 + 子句集蕴含比较）与语义侧（语义评审交叉验证）双侧交叉"

# 形式化侧的子句蕴含判定结果
STRENGTHENED = "strengthened"
EQUIVALENT = "equivalent"
WEAKENED = "weakened"
UNDECIDED = "uncertain"

__all__ = ["check_i4", "METHOD"]


@guarded("I4", METHOD)
def check_i4(mod: Modification, state: SystemState) -> CheckResult:
    """检查本次修改是否削弱了约束集 Φ。"""
    evidence: list[str] = []
    detail: dict[str, Any] = {}

    removed = [str(c) for c in (getattr(mod, "removed_constraints", None) or [])]
    added = [str(c) for c in (getattr(mod, "added_constraints", None) or [])]
    rewrites = [(str(o), str(n)) for o, n in (getattr(mod, "constraint_rewrites", None) or [])]

    # -- 一、组装待判定的子句对 -------------------------------------------
    compensation = _compensation_map(added, rewrites)
    pairs: list[tuple[str, str, str]] = []
    consumed_rewrite_old: set[str] = set()
    for rc in removed:
        key = normalize_text(rc)
        if key in compensation:
            pairs.append((rc, compensation[key], "删除后补入（等价改写候选）"))
            consumed_rewrite_old.add(key)
        else:
            pairs.append((rc, "", "删除"))
    for old, new in rewrites:
        if normalize_text(old) in consumed_rewrite_old:
            continue  # 与上面的删除-补入对重复，避免重复计票
        pairs.append((old, new, "改写"))

    detail["pairs"] = [{"old": o, "new": n, "kind": k} for o, n, k in pairs]
    evidence.append(
        f"约束面改动：删除 {len(removed)} 条、新增 {len(added)} 条、改写 {len(rewrites)} 条，"
        f"实际送检子句对 {len(pairs)} 组"
    )
    if added:
        evidence.append(
            f"新增约束 {len(added)} 条（加强方向，不构成弱化）：{'、'.join(added[:3])}"
            + ("等" if len(added) > 3 else "")
        )

    # -- 二、双侧判定 -----------------------------------------------------
    judge = _safe_judge()
    formal_results: list[dict[str, Any]] = []
    semantic_results: list[dict[str, Any]] = []
    for old, new, kind in pairs:
        f_verdict = _formal_implication(old, new)
        formal_results.append({"old": old, "new": new, "kind": kind, "verdict": f_verdict})
        try:
            weakened, reason = judge.judge(old, new)
            s_verdict = WEAKENED if weakened else "not_weakened"
        except Exception as exc:  # noqa: BLE001 —— 评审器异常必须降级为不确定
            s_verdict = UNDECIDED
            reason = f"语义评审器异常：{type(exc).__name__}: {exc}"
        semantic_results.append(
            {"old": old, "new": new, "kind": kind, "verdict": s_verdict, "reason": reason}
        )
        evidence.append(
            f"子句对（{kind}）「{_short(old)}」→「{_short(new)}」："
            f"形式化侧={f_verdict}，语义侧={s_verdict}（{_short(reason, 90)}）"
        )

    detail["formal_side"] = formal_results
    detail["semantic_side"] = semantic_results

    formal_overall = _overall([r["verdict"] for r in formal_results])
    semantic_overall = _overall([r["verdict"] for r in semantic_results])
    inconsistent = [
        f
        for f, s in zip(formal_results, semantic_results)
        if _conflict(f["verdict"], s["verdict"])
    ]
    detail["formal_overall"] = formal_overall
    detail["semantic_overall"] = semantic_overall
    detail["inconsistent_pairs"] = len(inconsistent)

    # -- 三、汇总判定 -----------------------------------------------------
    m = len(pairs)
    k = len(inconsistent)
    ratio = (k / m) if m else 0.0
    error_bound = (
        "语义等价不可判定，残余漏放率以双侧不一致样本占比上界估计："
        f"本次送检子句对 m={m}，双侧不一致 k={k}（占比 {ratio:.3f}）；"
        "该占比只是样本估计，样本量过小不足以构成总体上界，"
        "总体漏放率须由 §3.4 阈值标定实验给出；"
        "此外形式化侧的蕴含判断本身是启发式近似（义务强度 + 量词方向 + 内容词包含），"
        "无法覆盖全部自然语言改写形态"
    )

    if not pairs:
        evidence.append("本次提案未删除、未新增、未改写任何约束子句")
        return CheckResult(
            invariant="I4",
            status=CheckStatus.PASS,
            summary="约束守恒满足：本次提案未触及约束集 Φ，无删除与弱化行为",
            evidence=evidence,
            method=METHOD,
            error_bound=(
                "本次提案未改动约束集，样本不涉及语义等价判定；"
                "语义等价不可判定的一般性漏放风险不适用于本样本"
            ),
            detail=detail,
        )

    if formal_overall == WEAKENED and semantic_overall == WEAKENED:
        weakened_pairs = sum(1 for r in formal_results if r["verdict"] == WEAKENED)
        evidence.append(f"双侧一致判定为弱化（{weakened_pairs} 组子句被判为弱化）")
        return CheckResult(
            invariant="I4",
            status=CheckStatus.FAIL,
            summary=(
                f"约束守恒违反：形式化侧与语义侧一致判定约束被削弱"
                f"（{weakened_pairs} 组子句被判为弱化）"
            ),
            evidence=evidence,
            method=METHOD,
            error_bound=error_bound,
            detail=detail,
        )

    if formal_overall == "not_weakened" and semantic_overall == "not_weakened":
        evidence.append("双侧一致判定为未弱化（等价改写或加强）")
        return CheckResult(
            invariant="I4",
            status=CheckStatus.PASS,
            summary="约束守恒满足：形式化侧与语义侧一致认为约束集未被削弱",
            evidence=evidence,
            method=METHOD,
            error_bound=error_bound,
            detail=detail,
        )

    # 两侧结论不一致（或有一侧无法判定）→ 转人工裁决
    reason = _mismatch_reason(formal_overall, semantic_overall)
    evidence.append(f"双侧结论比对：形式化侧={formal_overall}，语义侧={semantic_overall}")
    return CheckResult(
        invariant="I4",
        status=CheckStatus.UNCERTAIN,
        summary=f"形式化侧与语义侧结论不一致，需人工裁决（{reason}）",
        evidence=evidence,
        method=METHOD,
        error_bound=error_bound,
        detail=detail,
    )


# --------------------------------------------------------------------------
# 内部实现
# --------------------------------------------------------------------------


def _formal_implication(old: str, new: str) -> str:
    """形式化侧的子句蕴含判断：新子句是否蕴含旧子句（即是否至少一样强）。

    启发式：义务强度分（含量词方向、例外条款、否定表述）比较 + 核心内容词包含关系。
    无法判定时返回 ``uncertain``，绝不猜。
    """
    if not (old or "").strip():
        return STRENGTHENED  # 原约束为空，属于新增
    if not (new or "").strip():
        return WEAKENED  # 新约束为空，等价于删除

    s_old = strength_score(old)
    s_new = strength_score(new)
    if s_new > s_old:
        return STRENGTHENED
    if s_new < s_old:
        return WEAKENED

    t_old = content_tokens(old)
    t_new = content_tokens(new)
    if t_old and t_old <= t_new:
        return EQUIVALENT
    if not t_old and not t_new:
        return EQUIVALENT
    return UNDECIDED


def _compensation_map(added: list[str], rewrites: list[tuple[str, str]]) -> dict[str, str]:
    """被删除约束的补偿映射：归一化文本 → 补入/替换后的文本。

    若某条被删约束被同义文本补回，则它属于"等价改写"，不按删除处理。
    """
    comp: dict[str, str] = {}
    for c in added:
        comp.setdefault(normalize_text(c), c)
    for old, new in rewrites:
        comp.setdefault(normalize_text(old), new)
    return comp


def _overall(verdicts: list[str]) -> str:
    """把多组子句的判定汇总成一个总体结论。"""
    if not verdicts:
        return "not_weakened"
    if any(v == WEAKENED for v in verdicts):
        return WEAKENED
    if any(v == UNDECIDED for v in verdicts):
        return UNDECIDED
    return "not_weakened"


def _conflict(formal: str, semantic: str) -> bool:
    """两侧对同一子句对是否给出冲突结论。"""
    f_weakened = formal == WEAKENED
    s_weakened = semantic == WEAKENED
    if f_weakened != s_weakened:
        return True
    return UNDECIDED in (formal, semantic)


def _mismatch_reason(formal: str, semantic: str) -> str:
    if formal == WEAKENED and semantic == "not_weakened":
        return "形式化侧判定为弱化（删除或蕴含不成立），语义侧判定为未弱化"
    if formal == "not_weakened" and semantic == WEAKENED:
        return "形式化侧判定为等价或加强，语义侧判定为弱化"
    if formal == WEAKENED and semantic == UNDECIDED:
        return "形式化侧判定为弱化，语义侧未能给出确定结论"
    if formal == UNDECIDED and semantic == WEAKENED:
        return "语义侧判定为弱化，形式化侧未能判定蕴含关系"
    if formal == UNDECIDED and semantic == "not_weakened":
        return "形式化侧未能判定蕴含关系，语义侧判定为未弱化"
    if formal == "not_weakened" and semantic == UNDECIDED:
        return "语义侧未能给出确定结论"
    return "两侧结论未能对齐"


def _safe_judge():
    """取语义侧评审器，取不到时退回本地启发式评审器。"""
    try:
        return get_judge(None)
    except Exception:  # noqa: BLE001 —— 配置不可读也不能让检查失败
        from .semantic import HeuristicSemanticJudge

        return HeuristicSemanticJudge(None)


def _short(text: str, limit: int = 40) -> str:
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"
