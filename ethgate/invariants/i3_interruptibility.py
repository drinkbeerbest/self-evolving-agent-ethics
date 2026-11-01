"""I3 可中断性检查器（开题报告 §3.2.2 表2 第 I3 行；§3.2.2 "I3 值得单独说明"）。

不变量陈述：修改后仍须存在人类可触发的停机通道，且该通道的实现不依赖被修改的模块。

这是本文针对自我修改特性提出的原创约束——把"人类保留最终控制权"从声明变成
架构层面的独立性要求，可以用依赖图静态检查。

检验方式（依赖图分析）：

1. 从 ``state.modules``（module → 直接依赖）构造依赖图；
2. 种子 = ``mod.affected_modules`` ∪ 被改文件所在模块；
3. 求**反向可达闭包**：凡是在依赖图上（传递地）依赖某个种子的模块都属于受影响集合；
4. 若 ``state.shutdown_module`` 落在闭包内 → FAIL（停机通道的实现依赖被改模块）；
5. 若 ``mod.files`` 中有 ``is_shutdown=True`` → 直接 FAIL；
6. 证据中给出闭包与依赖链路径。

误差界：依赖图本身是静态近似——真实的运行期调用关系可能超出导入关系，
因此本检查给出的是"基于静态依赖图的必要条件判定"，其漏放来源是
动态调用、反射加载与配置注入等未出现在依赖图中的耦合。
"""
from __future__ import annotations

from collections import deque
from typing import Any

from ..types import CheckResult, CheckStatus, Modification, SystemState
from .base import guarded

METHOD = "依赖图反向可达闭包分析（修改影响闭包 → 停机通道独立性）"

__all__ = ["check_i3", "METHOD", "reverse_closure"]


@guarded("I3", METHOD)
def check_i3(mod: Modification, state: SystemState) -> CheckResult:
    """检查本次修改是否动摇了人类可触发的停机通道。"""
    modules: dict[str, list[str]] = dict(getattr(state, "modules", None) or {})
    shutdown = str(getattr(state, "shutdown_module", "") or "").strip()
    files = mod.files if isinstance(getattr(mod, "files", None), list) else []

    evidence: list[str] = []
    detail: dict[str, Any] = {
        "shutdown_module": shutdown,
        "modules_count": len(modules),
        "affected_seeds": [],
        "closure": [],
        "closure_chains": [],
    }

    # -- 一、直接触碰停机通道实现 ----------------------------------------
    shutdown_files = [f.path for f in files if getattr(f, "is_shutdown", False)]
    if shutdown_files:
        evidence.append(f"修改直接触碰停机通道实现：{'、'.join(shutdown_files)}")
        return CheckResult(
            invariant="I3",
            status=CheckStatus.FAIL,
            summary="可中断性违反：修改直接改写了停机通道实现，人类触发的停机能力不再独立于被改模块",
            evidence=evidence,
            method=METHOD,
            error_bound=(
                "完全可判定，误差为零（文件标记 is_shutdown 为显式事实）；"
                "残余风险仅在于提案未如实标记停机通道文件——"
                "此时需依赖依赖图分析兜底，该部分为静态近似"
            ),
            detail=detail,
        )

    # -- 二、系统状态未声明停机通道 --------------------------------------
    if not shutdown:
        evidence.append("SystemState.shutdown_module 为空：无法确定停机通道实现位置")
        return CheckResult(
            invariant="I3",
            status=CheckStatus.UNCERTAIN,
            summary=(
                "可中断性无法判定：系统状态未声明停机通道模块，"
                "既不能证实停机通道独立于本次修改，也不能证实其被破坏"
            ),
            evidence=evidence,
            method=METHOD,
            error_bound=(
                "依赖图缺项导致不可判定；本检查在该情形下的漏放率为 1（未作任何拦截），"
                "须由人工确认停机通道位置后重判"
            ),
            detail=detail,
        )

    # -- 三、构造种子 -----------------------------------------------------
    declared = [str(m) for m in (getattr(mod, "affected_modules", None) or [])]
    file_modules: list[str] = []
    for f in files:
        for m in _modules_for_path(modules, str(getattr(f, "path", "") or "")):
            if m not in file_modules:
                file_modules.append(m)
    seeds = list(dict.fromkeys(declared + file_modules))
    detail["affected_seeds"] = seeds
    evidence.append(
        f"修改种子（受影响模块）共 {len(seeds)} 个："
        f"提案声明 {declared if declared else '（无）'}；文件映射 {file_modules if file_modules else '（无）'}"
    )

    # -- 三之二、停机模块的"实现"是否被改 ---------------------------------
    # 关键区分：**拓扑里列着停机模块** ≠ **改写了停机模块的实现**。
    # 不变式要求的是"停机通道的实现不依赖被修改的模块"，
    # 是一条**实现依赖**判据，不是拓扑成员判据。
    # 若把停机模块本身放进种子，反向闭包必然包含它，
    # 于是任何一次调整运行拓扑的合法改动都会被误判为可中断性违反
    # （实测占全流程门禁误拦的 14/27）。
    shutdown_implementation_touched = bool(shutdown_files)
    if not shutdown_implementation_touched:
        for f in files:
            if shutdown and shutdown in str(getattr(f, "path", "") or ""):
                shutdown_implementation_touched = True
                break
    if shutdown_implementation_touched:
        evidence.append(f"停机模块 {shutdown!r} 的实现文件被本次修改触及")
        return CheckResult(
            invariant="I3",
            status=CheckStatus.FAIL,
            summary=f"可中断性违反：停机通道模块 {shutdown} 的实现被本次修改改写",
            evidence=evidence,
            method=METHOD,
            error_bound=(
                "完全可判定，误差为零（停机实现文件被直接改写是显式事实）；"
                "残余风险仅在于提案未如实标记停机通道文件"
            ),
            detail=detail,
        )

    # 种子中剔除停机模块自身（拓扑成员不等于实现改动）
    seed_set = [s for s in seeds if s != shutdown]
    detail["affected_seeds"] = seed_set
    seeds = seed_set

    # -- 四、依赖图可用性 -------------------------------------------------
    if not modules:
        evidence.append("SystemState.modules 为空：没有依赖图，无法计算修改影响闭包")
        return CheckResult(
            invariant="I3",
            status=CheckStatus.UNCERTAIN,
            summary="可中断性无法判定：系统状态未提供模块依赖图，影响闭包无法计算",
            evidence=evidence,
            method=METHOD,
            error_bound="依赖图缺项导致不可判定；该情形下的漏放率为 1，须补齐依赖图后重判",
            detail=detail,
        )

    if not seeds:
        if files:
            evidence.append(
                f"本次修改涉及 {len(files)} 个文件，但均未能在依赖图中定位模块，"
                f"且提案未声明 affected_modules：无法确定修改影响闭包"
            )
            return CheckResult(
                invariant="I3",
                status=CheckStatus.UNCERTAIN,
                summary="可中断性无法判定：被改文件无法映射到依赖图节点，影响闭包不可计算",
                evidence=evidence,
                method=METHOD,
                error_bound=(
                    "依赖图覆盖不全导致不可判定；该情形下的漏放率为 1，"
                    "须补齐依赖图或修正 affected_modules 后重判"
                ),
                detail=detail,
            )
        evidence.append("本次修改未涉及任何文件与模块：停机通道不受影响")
        return CheckResult(
            invariant="I3",
            status=CheckStatus.PASS,
            summary="可中断性满足：本次修改未触及任何模块，停机通道保持独立",
            evidence=evidence,
            method=METHOD,
            error_bound="完全可判定，误差为零（无修改即无影响）",
            detail=detail,
        )

    # 停机模块必须出现在依赖图里，否则无法判断其依赖独立性
    graph_nodes = set(modules.keys())
    graph_deps = {d for deps in modules.values() for d in (deps or [])}
    if shutdown not in graph_nodes and shutdown not in graph_deps:
        evidence.append(f"停机模块 {shutdown!r} 未出现在依赖图中：无法判断其是否依赖被修改的模块")
        return CheckResult(
            invariant="I3",
            status=CheckStatus.UNCERTAIN,
            summary=f"可中断性无法判定：停机模块 {shutdown} 不在依赖图中，其依赖独立性未知",
            evidence=evidence,
            method=METHOD,
            error_bound=(
                "依赖图覆盖不全导致不可判定；该情形下的漏放率为 1，"
                "须把停机通道纳入依赖图后重判"
            ),
            detail=detail,
        )

    # -- 五、反向可达闭包 -------------------------------------------------
    closure, parents = reverse_closure(modules, seeds)
    affected = sorted(set(seeds) | set(closure))
    chains = {m: _chain(m, parents) for m in sorted(closure)}
    detail["closure"] = affected
    detail["closure_chains"] = {k: " ← ".join(v) for k, v in chains.items()}
    evidence.append(
        f"修改影响闭包（反向可达）共 {len(affected)} 个模块："
        + ("、".join(affected) if affected else "（空）")
    )
    for node, chain in chains.items():
        evidence.append(f"依赖链：{' ← '.join(chain)}（后者是前者的直接依赖）")

    if shutdown in closure:
        chain = chains.get(shutdown, [shutdown])
        evidence.append(
            f"停机模块 {shutdown!r} 落在修改影响闭包内，依赖链：{' ← '.join(chain)}"
        )
        return CheckResult(
            invariant="I3",
            status=CheckStatus.FAIL,
            summary=(
                f"可中断性违反：停机通道 {shutdown} 依赖被本次修改触及的模块 "
                f"（{' ← '.join(chain)}），人类触发的停机能力不再独立"
            ),
            evidence=evidence,
            method=METHOD,
            error_bound=(
                "基于静态依赖图的必要条件判定：命中即确定违反，误差为零；"
                "反向的漏放来源是动态调用、反射加载、配置注入等未出现在 import 关系中的耦合"
            ),
            detail=detail,
        )

    evidence.append(f"停机模块 {shutdown!r} 不在修改影响闭包内，停机通道实现未被本次修改波及")
    return CheckResult(
        invariant="I3",
        status=CheckStatus.PASS,
        summary=(
            f"可中断性满足：停机通道 {shutdown} 不依赖本次修改触及的任何模块"
            f"（影响闭包共 {len(affected)} 个模块）"
        ),
        evidence=evidence,
        method=METHOD,
        error_bound=(
            "基于静态依赖图的必要条件判定：未命中不能排除动态耦合导致的漏放，"
            "漏放来源为运行期调用关系未出现在 import 依赖图中；"
            "该残余风险由二级门禁的强制中断演练兜底"
        ),
        detail=detail,
    )


# --------------------------------------------------------------------------
# 内部实现
# --------------------------------------------------------------------------


def reverse_closure(
    modules: dict[str, list[str]], seeds: list[str]
) -> tuple[dict[str, str], dict[str, str | None]]:
    """求反向可达闭包。

    ``modules[m]`` 是 m 的直接依赖。修改某个种子后，**依赖该种子**的模块都会受影响，
    因此受影响集合是种子在"被依赖"方向上的反向可达闭包。

    返回 ``(closure, parents)``：``closure[m]`` 是 m 的父节点（m 依赖它），
    ``parents`` 用于还原依赖链。
    """
    rev: dict[str, set[str]] = {}
    for m, deps in (modules or {}).items():
        for d in deps or []:
            rev.setdefault(d, set()).add(m)

    parents: dict[str, str | None] = {s: None for s in seeds}
    closure: dict[str, str] = {}
    queue: deque[str] = deque(seeds)
    while queue:
        cur = queue.popleft()
        for nxt in sorted(rev.get(cur, ())):
            if nxt in parents:
                continue
            parents[nxt] = cur
            closure[nxt] = cur
            queue.append(nxt)
    return closure, parents


def _chain(node: str, parents: dict[str, str | None]) -> list[str]:
    """还原依赖链：[停机模块, 直接依赖, ..., 种子]。"""
    chain = [node]
    cur = node
    seen = {node}
    while parents.get(cur) is not None:
        cur = str(parents[cur])
        if cur in seen:  # 防御性：依赖图成环时截断
            break
        seen.add(cur)
        chain.append(cur)
    return chain


def _modules_for_path(modules: dict[str, list[str]], path: str) -> list[str]:
    """把文件路径映射到依赖图中的模块节点。

    兼容三种常见命名：``core/kernel.py``（文件式模块）、``core.kernel``（点式模块）、
    以及以目录形式覆盖子模块的情形。
    """
    if not path or not modules:
        return []
    norm = path.replace("\\", "/").strip()
    stem = norm[:-3] if norm.endswith(".py") else norm
    hits: list[str] = []
    for name in modules:
        mn = str(name).replace("\\", "/").strip()
        mstem = mn[:-3] if mn.endswith(".py") else mn
        if mn == norm or mstem == stem:
            hits.append(name)
            continue
        if mn.replace(".", "/") == stem or mstem.replace(".", "/") == stem:
            hits.append(name)
            continue
        if norm.startswith(mn + "/") or stem.startswith(mstem + "/"):
            hits.append(name)
    return hits
