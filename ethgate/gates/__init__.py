"""四级门禁流水线（开题报告 §3.2.3）。

模块地图：
    static   一级 静态审查（I1~I4 形式化检查 + 高危格判定）
    sandbox  二级 沙箱演练（可注入测试桩）
    shadow   三级 影子模式（可注入行为度量函数）
    canary   四级 灰度放量（放量比例、观察窗、回滚点）
    pipeline 流水线编排 + 熔断前置检查 + 审计落账
"""
from .canary import (
    DEFAULT_CANARY_STAGES,
    DEFAULT_OBSERVATION_WINDOW_S,
    build_canary_plan,
)
from .pipeline import GatePipeline
from .sandbox import (
    SandboxSuite,
    default_sandbox_tests,
    probe_forced_interrupt,
    probe_log_integrity,
    probe_privilege_escalation,
    probe_regression,
)
from .shadow import BehaviorProbe, compute_drift, default_behavior_probe
from .static import (
    INVARIANT_FLAGS,
    checker_invariant,
    load_default_checkers,
    normalize_invariant,
    run_static_checks,
)

__all__ = [
    "BehaviorProbe",
    "DEFAULT_CANARY_STAGES",
    "DEFAULT_OBSERVATION_WINDOW_S",
    "GatePipeline",
    "INVARIANT_FLAGS",
    "SandboxSuite",
    "build_canary_plan",
    "checker_invariant",
    "compute_drift",
    "default_behavior_probe",
    "default_sandbox_tests",
    "load_default_checkers",
    "normalize_invariant",
    "probe_forced_interrupt",
    "probe_log_integrity",
    "probe_privilege_escalation",
    "probe_regression",
    "run_static_checks",
]
