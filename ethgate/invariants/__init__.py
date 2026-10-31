"""四条伦理不变量的可判定检验（开题报告 §3.2.2 表2）。

四条不变量的检验方式与可判定性（表2）：

===== ====================== ================================== ==========
ID    内容                   检验方式                            可判定性
===== ====================== ================================== ==========
I1    权限单调性             工具表与系统调用白名单差集运算      完全可判定
I2    审计完备性             日志字段完备性 + 随机抽样重放       可判定，含抽样误差
I3    可中断性               依赖图分析（停机模块是否在影响闭包内） 可判定
I4    约束守恒               形式化子句集蕴含 + 语义侧交叉验证   部分可判定
===== ====================== ================================== ==========

每个检查器的签名固定为 ``check_iN(mod, state) -> CheckResult``，
且**绝不抛异常**：不确定时返回 ``CheckStatus.UNCERTAIN``，
让门禁流水线把这类提案升级到沙箱或人工裁决，而不是整体崩掉。
"""
from __future__ import annotations

from . import semantic
from .i1_permission import check_i1
from .i2_audit import check_i2
from .i3_interruptibility import check_i3
from .i4_constraint import check_i4
from .semantic import HeuristicSemanticJudge, LLMJudge, get_judge

ALL_CHECKERS = [check_i1, check_i2, check_i3, check_i4]

__all__ = [
    "check_i1",
    "check_i2",
    "check_i3",
    "check_i4",
    "ALL_CHECKERS",
    "semantic",
    "HeuristicSemanticJudge",
    "LLMJudge",
    "get_judge",
]
