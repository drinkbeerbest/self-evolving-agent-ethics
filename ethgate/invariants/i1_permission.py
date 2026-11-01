"""I1 权限单调性检查器（开题报告 §3.2.2 表2 第 I1 行）。

不变量陈述：修改后可达资源集不得超出"修改前授权闭包 ∪ 预设增量"的并集。

检验方式：工具表与系统调用白名单的差集运算（完全可判定，§3.2.2 表2）。
实现要点：

* 比较 ``mod.new_tools`` / ``mod.new_syscalls`` 与 ``state.tool_table`` /
  ``state.syscalls_allowed``，落在差集里的新增项即为权限扩张；
* 新增网络主机 ``mod.new_network_hosts`` 同样属于可达资源集扩大（外泄面扩张），
  一并计入证据并参与判定；
* 若新增项落在预授权白名单（``mod.detail["preauthorized"]``）内，则视为预设增量，不判扩张。

误差界：差集运算是精确的集合比较，判定本身没有近似误差；残余风险只来自
"预授权白名单本身是否可信"——若白名单由被审查方自己填写，则存在漏放风险。
"""
from __future__ import annotations

from typing import Any

from ..types import CheckResult, CheckStatus, Modification, SystemState
from .base import guarded

METHOD = "工具表/系统调用白名单/网络主机白名单差集运算（授权闭包增量检查）"

__all__ = ["check_i1", "METHOD"]


@guarded("I1", METHOD)
def check_i1(mod: Modification, state: SystemState) -> CheckResult:
    """检查修改是否扩张了可达资源集。"""
    auth_tools = list(state.tool_table or [])
    auth_syscalls = list(state.syscalls_allowed or [])
    pre = _preauthorized(mod)

    new_tools = [str(x) for x in (mod.new_tools or [])]
    new_syscalls = [str(x) for x in (mod.new_syscalls or [])]
    new_hosts = [str(x) for x in (mod.new_network_hosts or [])]

    expanded_tools = [t for t in new_tools if t not in auth_tools and t not in pre["tools"]]
    expanded_syscalls = [s for s in new_syscalls if s not in auth_syscalls and s not in pre["syscalls"]]
    expanded_hosts = [h for h in new_hosts if h not in pre["hosts"]]

    evidence: list[str] = [
        f"授权工具表 state.tool_table 共 {len(auth_tools)} 项：{_fmt(auth_tools)}",
        f"授权系统调用白名单 state.syscalls_allowed 共 {len(auth_syscalls)} 项：{_fmt(auth_syscalls)}",
        f"提案新增工具 {len(new_tools)} 项：{_fmt(new_tools)}",
        f"提案新增系统调用 {len(new_syscalls)} 项：{_fmt(new_syscalls)}",
        f"提案新增网络主机 {len(new_hosts)} 项：{_fmt(new_hosts)}",
    ]
    if any(pre.values()):
        evidence.append(
            f"预授权白名单（预设增量）：工具 {_fmt(sorted(pre['tools']))}；"
            f"系统调用 {_fmt(sorted(pre['syscalls']))}；网络主机 {_fmt(sorted(pre['hosts']))}"
        )

    detail: dict[str, Any] = {
        "authorized_tools": auth_tools,
        "authorized_syscalls": auth_syscalls,
        "new_tools": new_tools,
        "new_syscalls": new_syscalls,
        "new_network_hosts": new_hosts,
        "expanded_tools": expanded_tools,
        "expanded_syscalls": expanded_syscalls,
        "expanded_network_hosts": expanded_hosts,
        "preauthorized": {k: sorted(v) for k, v in pre.items()},
    }

    total_expanded = len(expanded_tools) + len(expanded_syscalls) + len(expanded_hosts)
    if total_expanded:
        if expanded_tools:
            evidence.append(f"权限扩张：新增工具未在授权闭包内 → {_fmt(expanded_tools)}")
        if expanded_syscalls:
            evidence.append(f"权限扩张：新增系统调用未在白名单内 → {_fmt(expanded_syscalls)}")
        if expanded_hosts:
            evidence.append(f"外泄面扩张：新增网络主机未在预设增量内 → {_fmt(expanded_hosts)}")
        return CheckResult(
            invariant="I1",
            status=CheckStatus.FAIL,
            summary=(
                f"权限单调性违反：可达资源集超出修改前授权闭包与预设增量并集"
                f"（新增工具 {len(expanded_tools)}、新增系统调用 {len(expanded_syscalls)}、"
                f"新增网络主机 {len(expanded_hosts)}）"
            ),
            evidence=evidence,
            method=METHOD,
            error_bound=(
                "完全可判定，误差为零（差集运算是精确集合比较）；"
                "残余不确定性仅来自预授权白名单本身的可信度——"
                "若白名单由被审查方自行填写，则该部分存在漏放风险"
            ),
            detail=detail,
        )

    evidence.append("差集为空：修改后可达资源集未超出授权闭包 ∪ 预设增量")
    return CheckResult(
        invariant="I1",
        status=CheckStatus.PASS,
        summary="权限单调性满足：新增的工具/系统调用/网络主机全部落在授权闭包或预授权增量内",
        evidence=evidence,
        method=METHOD,
        error_bound=(
            "完全可判定，误差为零（差集运算是精确集合比较）；"
            "残余不确定性仅来自预授权白名单本身的可信度"
        ),
        detail=detail,
    )


def _preauthorized(mod: Modification) -> dict[str, set[str]]:
    """取出预授权白名单（预设增量）。

    ``Modification`` 类型本身没有 ``detail`` 字段，这里用 ``getattr`` 容忍运行期附加的
    白名单（契约推荐的 ``mod.detail["preauthorized"]``），同时兼容
    ``mod.detail["preauthorized_tools"]`` / ``..._syscalls`` / ``..._hosts`` 三类分桶写法。
    """
    detail = getattr(mod, "detail", None)
    if not isinstance(detail, dict):
        detail = {}
    out: dict[str, set[str]] = {"tools": set(), "syscalls": set(), "hosts": set()}

    def _as_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        try:
            return [str(v) for v in value]
        except TypeError:
            return [str(value)]

    # 全局白名单：对三类新增项都生效
    for item in _as_list(detail.get("preauthorized")) + _as_list(getattr(mod, "preauthorized", None)):
        for key in out:
            out[key].add(item)
    # 分桶白名单
    for key, bucket in (
        ("preauthorized_tools", "tools"),
        ("preauthorized_syscalls", "syscalls"),
        ("preauthorized_hosts", "hosts"),
    ):
        for item in _as_list(detail.get(key)) + _as_list(getattr(mod, key, None)):
            out[bucket].add(item)
    return out


def _fmt(items: list[str], limit: int = 8) -> str:
    if not items:
        return "（空）"
    head = "、".join(items[:limit])
    if len(items) > limit:
        head += f" 等 {len(items)} 项"
    return head
