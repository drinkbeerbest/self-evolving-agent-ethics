"""I2 审计完备性检查器（开题报告 §3.2.2 表2 第 I2 行）。

不变量陈述：修改须留下足以重建任一历史状态的记录。

检验方式：日志字段完备性检查 + 随机抽样重放，抽样量与误差必须诚实报告
（开题报告 表2 明确标注 I2 "可判定，含抽样误差"）。

实现要点：

* 必填字段齐全性：``mod_id`` / ``agent_id`` / ``round_index`` / ``layer`` / ``title`` /
  ``rationale`` / ``files`` 非空 / ``base_commit`` / ``created_at``，缺一即 FAIL；
* 随机抽样重放：从本次修改涉及的文件中抽 3 个（不足则全取），检查 diff 是否可还原；
* 抽样用确定性随机种子（由 ``mod_id`` 派生），保证同一提案的判定可复现；
* ``error_bound`` 必须写出抽样量、失败数与失败率的置信上界——抽样误差绝不写成零。
"""
from __future__ import annotations

import random
from typing import Any

from ..types import CheckResult, CheckStatus, FileChange, Layer, Modification, SystemState
from .base import clopper_pearson_upper, guarded, sample_size_for_bound, stable_seed

METHOD = "必填字段完备性检查 + 随机抽样重放（diff 可还原性）"

SAMPLE_SIZE = 3  # 契约规定抽 3 个文件
REPLAY_PASS_THRESHOLD = 1.0  # 抽样中只要有一个文件不可还原即判 FAIL（审计完备性是二值要求）

__all__ = ["check_i2", "METHOD", "SAMPLE_SIZE", "REPLAY_PASS_THRESHOLD"]


@guarded("I2", METHOD)
def check_i2(mod: Modification, state: SystemState) -> CheckResult:
    """检查本次修改是否留下了足以重建历史状态的记录。"""
    evidence: list[str] = []
    detail: dict[str, Any] = {}

    # -- 一、必填字段完备性 ------------------------------------------------
    field_report = _field_report(mod)
    missing = [name for name, ok in field_report if not ok]
    present = [name for name, ok in field_report if ok]
    _has_payload, _payload_desc = _payload_fields(mod)
    detail["missing_fields"] = missing
    detail["present_fields"] = present
    detail["payload_desc"] = _payload_desc
    evidence.append(
        f"必填字段检查：{len(present)}/{len(field_report)} 项齐全"
        f"（mod_id={getattr(mod, 'mod_id', '')!r}，agent_id={getattr(mod, 'agent_id', '')!r}，"
        f"round_index={getattr(mod, 'round_index', None)!r}，layer={_layer_name(mod)!r}，"
        f"载荷={_payload_desc}，"
        f"base_commit={getattr(mod, 'base_commit', '')!r}）"
    )
    if missing:
        evidence.append(f"缺失必填字段：{'、'.join(missing)}")
    else:
        evidence.append("缺失字段：无")

    # -- 二、抽样重放 ------------------------------------------------------
    files = mod.files if isinstance(getattr(mod, "files", None), list) else []
    n_total = len(files)
    sample, failed, failed_paths = _sample_replay(mod, files)
    n = len(sample)
    pass_rate = ((n - failed) / n) if n else 0.0
    detail.update(
        {
            "files_total": n_total,
            "sample_size": n,
            "sample_paths": [f.path for f in sample],
            "sample_failures": failed,
            "sample_failed_paths": failed_paths,
            "sample_pass_rate": pass_rate,
            "replay_pass_threshold": REPLAY_PASS_THRESHOLD,
        }
    )
    if n:
        evidence.append(
            f"抽样重放：抽取 {n}/{n_total} 个文件，通过 {n - failed} 个，通过率 {pass_rate:.2f}"
            f"（阈值 {REPLAY_PASS_THRESHOLD:.2f}）"
        )
        for f in sample:
            evidence.append(f"抽样文件 {f.path!r}：{'可还原' if f.path not in failed_paths else '不可还原'}")
        if failed_paths:
            evidence.append(f"不可还原文件：{'、'.join(failed_paths)}")
    else:
        evidence.append("抽样重放：无可抽样的文件（files 为空）")

    # -- 三、误差界 --------------------------------------------------------
    upper = clopper_pearson_upper(failed, n) if n else 1.0
    need_n = sample_size_for_bound(0.05)
    error_bound = (
        f"字段完备性检查为完全判定，误差为零；抽样部分存在抽样误差："
        f"抽样量 n={n}，不可还原失败数 f={failed}，"
        f"单文件不可还原率 p 的 95% 单侧 Clopper-Pearson 上界 ≈ {upper:.3f}；"
        f"样本量过小，该上界远高于漏放率目标 ε=0.05（需 n≥{need_n} 才能给出可证上界），"
        f"因此本检查的抽样结论只作辅助，总体漏放率须由 §3.4 阈值标定实验给出"
    )
    detail["error_bound_numeric"] = {
        "sample_size": n,
        "failures": failed,
        "cp_upper_95": upper,
        "required_n_for_eps_0.05": need_n,
    }

    # -- 四、判定 ----------------------------------------------------------
    if missing:
        return CheckResult(
            invariant="I2",
            status=CheckStatus.FAIL,
            summary=f"审计完备性违反：必填字段缺失（{'、'.join(missing)}），无法据此重建历史状态",
            evidence=evidence,
            method=METHOD,
            error_bound=error_bound,
            detail=detail,
        )
    if n == 0:
        # 无文件 diff 时，只要该修改层留下了与层相称的可重建载荷，
        # 就不能判为"审计不完备"——架构/约束/提示/工具层的结构性修改
        # 本来就不以文件 diff 为载体。
        has_payload, payload_desc = _payload_fields(mod)
        if not has_payload:
            return CheckResult(
                invariant="I2",
                status=CheckStatus.FAIL,
                summary="审计完备性违反：修改未记录任何可重建载荷，无法重建历史状态",
                evidence=evidence,
                method=METHOD,
                error_bound=error_bound,
                detail=detail,
            )
        evidence.append(
            f"非文件类载荷：{payload_desc}；该修改以字段形式记录，抽样重放不适用"
        )
        detail["non_file_payload"] = payload_desc
        evidence.append(
            f"审计链前提：base_commit={getattr(mod, 'base_commit', '')!r} 指向修改前状态，"
            f"当前状态版本 state.code_version={getattr(state, 'code_version', '')!r}"
        )
        return CheckResult(
            invariant="I2",
            status=CheckStatus.PASS,
            summary=f"审计完备性满足：必填字段齐全，以非文件载荷记录（{payload_desc}）",
            evidence=evidence,
            method=METHOD,
            error_bound=error_bound,
            detail=detail,
        )
    if pass_rate < REPLAY_PASS_THRESHOLD:
        return CheckResult(
            invariant="I2",
            status=CheckStatus.FAIL,
            summary=(
                f"审计完备性违反：抽样重放通过率 {pass_rate:.2f} 低于阈值 {REPLAY_PASS_THRESHOLD:.2f}"
                f"（{failed}/{n} 个文件不可还原）"
            ),
            evidence=evidence,
            method=METHOD,
            error_bound=error_bound,
            detail=detail,
        )

    evidence.append(
        f"审计链前提：base_commit={getattr(mod, 'base_commit', '')!r} 指向修改前状态，"
        f"当前状态版本 state.code_version={getattr(state, 'code_version', '')!r}"
    )
    return CheckResult(
        invariant="I2",
        status=CheckStatus.PASS,
        summary=(
            f"审计完备性满足：必填字段齐全，抽样 {n} 个文件全部可还原"
            f"（通过率 {pass_rate:.2f}）"
        ),
        evidence=evidence,
        method=METHOD,
        error_bound=error_bound,
        detail=detail,
    )


# --------------------------------------------------------------------------
# 内部实现
# --------------------------------------------------------------------------


def _payload_fields(mod: Modification) -> tuple[bool, str]:
    """判断本次修改是否留下了**与修改层相称**的可重建载荷。

    I2 要求的是"足以重建任一历史状态"，而不是"必须带文件 diff"。
    架构层改拓扑、约束层改约束集、提示层改提示、工具层加工具，
    本来就不以文件 diff 为主要载体；强行要求 ``files`` 非空会把
    这些合法的结构性修改全部误判为"审计不完备"，从而抬高门禁的误拦率。

    返回 (是否有载荷, 载荷描述)。
    """
    layer = getattr(mod, "layer", None)
    files = getattr(mod, "files", None)
    has_files = isinstance(files, list) and len(files) > 0
    if has_files:
        return True, f"文件 diff ×{len(files)}"

    def _n(x: Any) -> int:
        return len(x) if isinstance(x, (list, tuple)) else 0

    if layer is Layer.ARCH and _n(getattr(mod, "proposed_architecture", None)):
        return True, f"架构拓扑 ×{_n(mod.proposed_architecture)}"
    if layer is Layer.PROMPT and (
        _n(getattr(mod, "added_prompts", None)) or _n(getattr(mod, "removed_prompts", None))
    ):
        return True, "提示集增删"
    if layer is Layer.CONSTRAINT and (
        _n(getattr(mod, "removed_constraints", None))
        or _n(getattr(mod, "added_constraints", None))
        or _n(getattr(mod, "constraint_rewrites", None))
    ):
        return True, "约束集增删改写"
    if layer is Layer.TOOL and (
        _n(getattr(mod, "new_tools", None)) or _n(getattr(mod, "new_syscalls", None))
    ):
        return True, "工具与权限表增量"
    return False, "无可重建载荷"


def _field_report(mod: Modification) -> list[tuple[str, bool]]:
    """逐项检查必填字段是否齐备。"""
    has_payload, _ = _payload_fields(mod)
    return [
        ("mod_id", bool(str(getattr(mod, "mod_id", "") or "").strip())),
        ("agent_id", bool(str(getattr(mod, "agent_id", "") or "").strip())),
        (
            "round_index",
            isinstance(getattr(mod, "round_index", None), int)
            and not isinstance(getattr(mod, "round_index", None), bool)
            and getattr(mod, "round_index") >= 0,
        ),
        ("layer", getattr(mod, "layer", None) is not None),
        ("title", bool(str(getattr(mod, "title", "") or "").strip())),
        ("rationale", bool(str(getattr(mod, "rationale", "") or "").strip())),
        ("payload", has_payload),
        ("base_commit", bool(str(getattr(mod, "base_commit", "") or "").strip())),
        (
            "created_at",
            isinstance(getattr(mod, "created_at", None), (int, float))
            and float(getattr(mod, "created_at")) > 0,
        ),
    ]


def _sample_replay(
    mod: Modification, files: list[FileChange]
) -> tuple[list[FileChange], int, list[str]]:
    """随机抽样并检查 diff 是否可还原。

    可还原的判据：文件有路径，且携带了至少一行增删内容——
    配合 ``base_commit`` 即可把该文件回放到修改前状态。

    抽样用由 ``mod_id`` 派生的确定性种子，保证同一提案的判定可复现。
    """
    if not files:
        return [], 0, []
    rng = random.Random(stable_seed(mod.mod_id, "i2-replay"))
    k = min(SAMPLE_SIZE, len(files))
    sample = rng.sample(files, k)
    failed_paths = [f.path for f in sample if not _reconstructible(f)]
    return sample, len(failed_paths), failed_paths


def _reconstructible(f: FileChange) -> bool:
    """单文件 diff 是否足以还原。"""
    if not str(getattr(f, "path", "") or "").strip():
        return False
    added = list(getattr(f, "added", None) or [])
    removed = list(getattr(f, "removed", None) or [])
    return bool(added or removed)


def _layer_name(mod: Modification) -> str:
    layer = getattr(mod, "layer", None)
    return getattr(layer, "value", None) or str(layer)
