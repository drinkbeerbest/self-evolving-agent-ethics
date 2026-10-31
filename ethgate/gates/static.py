"""一级门禁：静态审查（开题报告 §3.2.3 一级）。

一级门禁成本最低、毫秒级，可以在每次自我修改提案时执行。它做两件事：

  1. 跑 §3.2.2 的四条伦理不变量 I1~I4（受 config.enable_i1..i4 控制）；
  2. 查表判断该提案落在 18 格风险矩阵的高危格上（高危格强制加严）。

判定规则（开题报告 §3.2.3 + CONTRACT「任务 B」）：

  * 任一 checker FAIL              → ESCALATE（上报人工裁决），不直接拒绝；
                                     除非修改层为「约束」层且违反 I4，则直接 REJECT
  * 任一 checker UNCERTAIN         → SANDBOX（转入二级沙箱演练）
  * 全部 PASS 且落在高危格         → SANDBOX（高危格强制加严）
  * 全部 PASS 且非高危格           → PASS

对 `ethgate.invariants` 的导入是**延迟导入**（函数体内 import）：
四条检查器由并行任务实现，本模块必须能在其尚未就绪时独立 import 并运行。
"""
from __future__ import annotations

import re
from typing import Any, Sequence

from ..config import GateConfig
from ..types import CheckResult, CheckStatus, Modification, SystemState

__all__ = [
    "INVARIANT_FLAGS",
    "checker_invariant",
    "invoke_checker",
    "is_enabled",
    "load_default_checkers",
    "normalize_invariant",
    "run_static_checks",
]

# 不变量 ID → 配置开关名（config.enable_i1..i4）
INVARIANT_FLAGS: dict[str, str] = {
    "I1": "enable_i1",
    "I2": "enable_i2",
    "I3": "enable_i3",
    "I4": "enable_i4",
}

_INV_RE = re.compile(r"(?i)\b(i[1-4])\b")
_NAME_RE = re.compile(r"(?i)i([1-4])")


def normalize_invariant(raw: Any) -> str:
    """把检查器给出的不变量标识归一为 "I1".."I4"；无法识别时返回空串。"""
    if raw is None:
        return ""
    text = str(raw).strip().upper()
    if text in INVARIANT_FLAGS:
        return text
    m = _INV_RE.search(text)
    return m.group(1).upper() if m else ""


def checker_invariant(checker: Any) -> str:
    """从检查器函数名推断其负责的不变量（check_i1 → "I1"）。"""
    name = getattr(checker, "__name__", "") or ""
    m = _NAME_RE.search(name)
    return f"I{m.group(1)}" if m else ""


def is_enabled(config: GateConfig, invariant: str) -> bool:
    """该不变量在当前配置下是否启用；无法识别的 ID 一律启用。"""
    flag = INVARIANT_FLAGS.get(invariant)
    if flag is None:
        return True
    return bool(getattr(config, flag, True))


def invoke_checker(
    checker: Any, mod: Modification, state: SystemState
) -> CheckResult:
    """调用一个检查器。

    兼容两种实现形态：契约规定的是函数式 `check_iN(mod, state)`，
    而 `ethgate.types.InvariantChecker` 协议是方法式 `checker.check(mod, state)`。
    """
    method = getattr(checker, "check", None)
    if callable(method):
        return method(mod, state)
    return checker(mod, state)


def load_default_checkers() -> list[Any] | None:
    """延迟导入 `ethgate.invariants` 的四条检查器。

    并行任务尚未完成时返回 None（而不是抛异常），由调用方降级为 UNCERTAIN。
    """
    try:
        from ..invariants import ALL_CHECKERS  # 延迟导入：并行任务产物，可能尚未就绪
    except Exception:
        return None
    return list(ALL_CHECKERS)


def run_static_checks(
    mod: Modification,
    state: SystemState,
    config: GateConfig,
    checkers: Sequence[Any] | None = None,
) -> list[CheckResult]:
    """执行四条不变量检查，返回检查结果列表。

    参数 checkers 用于注入替身检查器（测试用）；为 None 时使用默认检查器。
    任何异常都被吞掉并降级为 UNCERTAIN——检查器崩溃不允许让流水线崩掉。
    """
    if checkers is None:
        checkers = load_default_checkers()
    if not checkers:
        return [
            CheckResult(
                invariant="ALL",
                status=CheckStatus.UNCERTAIN,
                summary="不变量检查器不可用，静态审查无法给出结论",
                evidence=["延迟导入 ethgate.invariants 失败：四条检查器尚未就绪"],
                method="模块可用性探测",
                error_bound="缺少检查器时漏放率上界为 1.0",
            )
        ]

    results: list[CheckResult] = []
    for checker in checkers:
        guess = checker_invariant(checker)
        if guess and not is_enabled(config, guess):
            continue  # 该不变量被配置关闭，跳过
        try:
            raw = invoke_checker(checker, mod, state)
        except Exception as exc:  # 契约要求：检查器不得让流水线崩溃
            raw = CheckResult(
                invariant=guess or "UNKNOWN",
                status=CheckStatus.UNCERTAIN,
                summary=f"检查器执行异常：{exc!r}",
                evidence=[
                    f"{getattr(checker, '__name__', checker)} 抛出 "
                    f"{type(exc).__name__}: {exc}"
                ],
                method="异常捕获降级",
                error_bound="异常样本按不确定处理，不得据此放行",
            )
        if raw is None:
            continue
        if not isinstance(raw, CheckResult):
            raw = CheckResult(
                invariant=guess or "UNKNOWN",
                status=CheckStatus.UNCERTAIN,
                summary=f"检查器返回了非法结果类型：{type(raw).__name__}",
                evidence=[repr(raw)[:200]],
                method="返回类型校验",
                error_bound="非法返回按不确定处理",
            )
        inv = normalize_invariant(getattr(raw, "invariant", "")) or guess
        if inv:
            raw.invariant = inv
            if not is_enabled(config, inv):
                continue
        results.append(raw)
    return results
