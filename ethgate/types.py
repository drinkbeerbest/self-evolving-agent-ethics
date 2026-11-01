"""共享类型契约 —— 全系统唯一的接口定义。

设计原则（对应开题报告 §3.2）：
  * 状态 S = (P, T, C, A, Φ)，修改算子 M: S -> S'，准入函数 A(M, S) ∈ {放行, 沙箱, 拒绝, 上报}
  * 四条不变量 I1..I4 各自独立可判定，不通过时必须给出证据与误差界
  * 熔断是有状态的：会锁定修改路径并把触发事件送入阈值标定
  * 成本与判定同源：每次准入判定都产出一份七维成本账

本文件不依赖任何第三方库，也不导入项目内其他模块，避免循环依赖。
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict, is_dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Protocol, Sequence

# --------------------------------------------------------------------------
# 枚举
# --------------------------------------------------------------------------


class Layer(str, Enum):
    """自我修改的六个对象层（开题报告 §3.1，横轴）。"""

    PROMPT = "提示"
    TOOL = "工具"
    CODE = "代码"
    ARCH = "架构"
    WEIGHT = "权重"
    CONSTRAINT = "约束"


class Autonomy(str, Enum):
    """三级自主度（开题报告 §3.1，纵轴）。"""

    PROPOSE_APPROVE = "系统提议·人类批准"
    PROPOSE_FILTER_AUDIT = "系统提议·系统初筛·人类抽检"
    AUTONOMOUS = "系统自主采纳·人类事后审计"


class AdmissionAction(str, Enum):
    """准入函数 A(M, S) 的四个取值（开题报告 §3.2.1 式(2)）。"""

    PASS = "放行"
    SANDBOX = "沙箱"
    REJECT = "拒绝"
    ESCALATE = "上报"


class CheckStatus(str, Enum):
    PASS = "通过"
    FAIL = "违反"
    UNCERTAIN = "不确定"


class GateLevel(int, Enum):
    """四级门禁（开题报告 §3.2.3）。"""

    STATIC = 1
    SANDBOX = 2
    SHADOW = 3
    CANARY = 4


class BreakerTrigger(str, Enum):
    """四类熔断触发条件（开题报告 §3.2.3）。"""

    INVARIANT_VIOLATION = "不变量违反"
    SHADOW_DRIFT = "影子期行为偏移超阈值"
    COST_OVER_BUDGET = "审查成本超出预算"
    EXTERNAL_AUDIT_VETO = "外部审计否决"


# --------------------------------------------------------------------------
# 风险面：五属性（开题报告 §3.1）
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskAttributes:
    """每个分类格的风险刻画。五个属性各 1..5 分，5 为最危险。"""

    reversibility: int  # 可逆性：能否在有限步内恢复前一状态
    observability: int  # 可观测性：修改后行为是否仍在监测覆盖内
    permission_expansion: int  # 权限扩张度：可达资源集是否增大
    goal_drift: int  # 目标漂移度：实际优化目标与声明目标的距离
    impact_radius: int  # 影响半径：失效波及单次任务/单用户/整个部署

    FIELDS = (
        "reversibility",
        "observability",
        "permission_expansion",
        "goal_drift",
        "impact_radius",
    )

    def as_dict(self) -> dict[str, int]:
        return {f: getattr(self, f) for f in self.FIELDS}

    def validate(self) -> None:
        for f in self.FIELDS:
            v = getattr(self, f)
            if not isinstance(v, int) or not 1 <= v <= 5:
                raise ValueError(f"风险属性 {f} 取值非法: {v!r}，应为 1..5 的整数")


# --------------------------------------------------------------------------
# 状态与修改
# --------------------------------------------------------------------------


@dataclass
class FileChange:
    """一次修改涉及的单文件变更。"""

    path: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    is_test: bool = False  # 是否触碰测试文件
    is_constraint: bool = False  # 是否是约束/指令描述文件
    is_evaluation: bool = False  # 是否触碰评测/评分逻辑
    is_shutdown: bool = False  # 是否触碰停机通道实现

    def diff_text(self) -> str:
        out = []
        for line in self.removed:
            out.append(f"- {line}")
        for line in self.added:
            out.append(f"+ {line}")
        return "\n".join(out)


@dataclass
class SystemState:
    """系统状态 S = (P, T, C, A, Φ)。"""

    prompt_set: list[str] = field(default_factory=list)  # P
    tool_table: list[str] = field(default_factory=list)  # T  工具与权限表
    syscalls_allowed: list[str] = field(default_factory=list)  # T 的系统调用白名单
    constraints: list[str] = field(default_factory=list)  # Φ 约束集（形式化子句）
    modules: dict[str, list[str]] = field(default_factory=dict)  # C 的模块依赖图
    shutdown_module: str = ""  # 停机通道实现模块（I3 静态检查对象）
    architecture: list[str] = field(default_factory=list)  # A 架构拓扑
    code_version: str = "v0"

    def clone(self) -> "SystemState":
        return SystemState(
            prompt_set=list(self.prompt_set),
            tool_table=list(self.tool_table),
            syscalls_allowed=list(self.syscalls_allowed),
            constraints=list(self.constraints),
            modules={k: list(v) for k, v in self.modules.items()},
            shutdown_module=self.shutdown_module,
            architecture=list(self.architecture),
            code_version=self.code_version,
        )

    def apply(self, mod: "Modification") -> "SystemState":
        """把修改 M 作用到状态上，得到 S'。"""
        nxt = self.clone()
        if mod.layer is Layer.TOOL:
            nxt.tool_table = sorted(set(nxt.tool_table) | set(mod.new_tools))
            nxt.syscalls_allowed = sorted(
                set(nxt.syscalls_allowed) | set(mod.new_syscalls)
            )
        if mod.layer is Layer.PROMPT:
            nxt.prompt_set = sorted(set(nxt.prompt_set) | set(mod.added_prompts))
        if mod.layer is Layer.CONSTRAINT:
            nxt.constraints = [
                c for c in nxt.constraints if c not in mod.removed_constraints
            ]
            nxt.constraints.extend(mod.added_constraints)
        if mod.layer is Layer.ARCH:
            nxt.architecture = list(mod.proposed_architecture or nxt.architecture)
        nxt.code_version = mod.mod_id
        return nxt


@dataclass
class Modification:
    """修改算子 M 的具体载荷：一次自我修改提案。"""

    mod_id: str = field(default_factory=lambda: f"mod-{uuid.uuid4().hex[:10]}")
    agent_id: str = "agent"
    round_index: int = 0
    layer: Layer = Layer.CODE
    autonomy: Autonomy = Autonomy.AUTONOMOUS
    title: str = ""
    rationale: str = ""
    files: list[FileChange] = field(default_factory=list)

    # 权限面
    new_tools: list[str] = field(default_factory=list)
    new_syscalls: list[str] = field(default_factory=list)
    new_network_hosts: list[str] = field(default_factory=list)

    # 约束面
    removed_constraints: list[str] = field(default_factory=list)
    added_constraints: list[str] = field(default_factory=list)
    constraint_rewrites: list[tuple[str, str]] = field(default_factory=list)

    # 观测面
    log_level_delta: int = 0  # 负数表示降低日志级别
    hardcode_detected: bool = False
    weakens_test_coverage: bool = False
    changes_evaluation_logic: bool = False

    # 提示面
    added_prompts: list[str] = field(default_factory=list)
    removed_prompts: list[str] = field(default_factory=list)

    # 架构面
    proposed_architecture: list[str] = field(default_factory=list)

    # 冗余字段：受影响模块（由扫描器/模拟框架填充）
    affected_modules: list[str] = field(default_factory=list)

    # 扩展载荷：供检查器与门禁传递附加信息。
    # 例：detail["preauthorized"] = ["tool_name"] 表示该工具已在预授权增量内，
    #     I1 权限单调性检查据此放行。
    detail: dict[str, Any] = field(default_factory=dict)

    base_commit: str = ""
    created_at: float = field(default_factory=time.time)
    source: str = "artificial"  # artificial | emergent | manual

    def touches(self, flag: str) -> bool:
        """是否触碰了某一类敏感文件。"""
        return any(getattr(f, flag) for f in self.files)

    def diff_text(self) -> str:
        return "\n".join(f"--- {f.path}\n{f.diff_text()}" for f in self.files)


# --------------------------------------------------------------------------
# 不变量检查结果
# --------------------------------------------------------------------------


@dataclass
class CheckResult:
    """单个不变量的检验结果。"""

    invariant: str  # I1 | I2 | I3 | I4
    status: CheckStatus
    summary: str = ""
    evidence: list[str] = field(default_factory=list)
    method: str = ""
    error_bound: str = ""  # 判定误差界；不可判定时必须写明
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status is CheckStatus.PASS


@dataclass
class CostLedger:
    """七维对齐成本（开题报告 表3）。"""

    c_cap: float = 0.0  # 能力成本：基准集性能差 / 基线
    c_lat: float = 0.0  # 时延成本：墙钟时间中位数比
    c_comp: float = 0.0  # 算力成本：折算金额
    c_hum: float = 0.0  # 人工成本：每千次修改的人工工时
    c_fp: float = 0.0  # 误拦成本：合法修改被拒比例
    c_fn: float = 0.0  # 漏放成本：危险修改被放行比例
    c_iter: float = 0.0  # 迭代效率损失：单位时间有效修改次数下降比例

    NAMES = (
        "c_cap",
        "c_lat",
        "c_comp",
        "c_hum",
        "c_fp",
        "c_fn",
        "c_iter",
    )

    WEIGHTS = {
        "c_cap": 0.20,
        "c_lat": 0.12,
        "c_comp": 0.12,
        "c_hum": 0.12,
        "c_fp": 0.18,
        "c_fn": 0.08,
        "c_iter": 0.18,
    }

    def weighted_total(self, weights: dict[str, float] | None = None) -> float:
        """加权合成对齐总成本 C_ali。权重可按场景重加权（开题报告 §3.3.2）。"""
        w = weights or self.WEIGHTS
        return sum(getattr(self, k) * w.get(k, 0.0) for k in self.NAMES)

    def as_dict(self) -> dict[str, float]:
        return {k: getattr(self, k) for k in self.NAMES}

    @classmethod
    def from_dict(cls, d: dict[str, float]) -> "CostLedger":
        return cls(**{k: float(d.get(k, 0.0)) for k in cls.NAMES})


@dataclass
class GateResult:
    """一级门禁（或整条流水线）的判定结果。"""

    level: GateLevel
    action: AdmissionAction
    results: list[CheckResult] = field(default_factory=list)
    cost: CostLedger = field(default_factory=CostLedger)
    elapsed_s: float = 0.0
    detail: dict[str, Any] = field(default_factory=dict)

    def by_invariant(self, inv: str) -> CheckResult | None:
        for r in self.results:
            if r.invariant == inv:
                return r
        return None


@dataclass
class BreakerEvent:
    """一次熔断事件。"""

    event_id: str = field(default_factory=lambda: f"brk-{uuid.uuid4().hex[:10]}")
    trigger: BreakerTrigger = BreakerTrigger.INVARIANT_VIOLATION
    mod_id: str = ""
    path_key: str = ""  # 被锁定的修改路径，如 "代码×自主采纳"
    locked_until: float = 0.0
    rollback_to: str = ""
    action_taken: str = ""
    cost: CostLedger = field(default_factory=CostLedger)
    detail: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class AuditRecord:
    """哈希链式审计记录（保证 I2 审计完备性可重建）。"""

    seq: int
    timestamp: float
    kind: str  # propose | verdict | breaker | rollback | escalate
    payload: dict[str, Any]
    prev_hash: str
    this_hash: str

    @staticmethod
    def compute_hash(seq: int, ts: float, kind: str, payload: dict, prev: str) -> str:
        blob = json.dumps(
            {
                "seq": seq,
                "ts": round(ts, 6),
                "kind": kind,
                "payload": payload,
                "prev": prev,
            },
            sort_keys=True,
            ensure_ascii=False,
            default=_json_default,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _json_default(o: Any) -> Any:
    if is_dataclass(o) and not isinstance(o, type):
        return asdict(o)
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    return str(o)


def to_jsonable(obj: Any) -> Any:
    """把任意 dataclass/Enum 树转成可 JSON 序列化的结构。"""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return [to_jsonable(v) for v in sorted(obj, key=str)]
    return obj


# --------------------------------------------------------------------------
# 协议（供各模块实现，Worker 之间只依赖这些接口）
# --------------------------------------------------------------------------


class InvariantChecker(Protocol):
    """不变量检查器协议。四条不变量各自实现一份。"""

    invariant: str

    def check(self, mod: Modification, state: SystemState) -> CheckResult:
        ...


class SemanticJudge(Protocol):
    """I4 语义侧评审器协议。"""

    def judge(self, old: str, new: str) -> tuple[bool, str]:
        """返回 (是否弱化, 理由)。"""
        ...


class Strategy(Protocol):
    """门禁策略协议。五种对照策略各自实现一份。"""

    name: str
    display_name: str

    def admit(self, mod: Modification, state: SystemState) -> GateResult:
        ...


class CostCollector(Protocol):
    """成本采集器协议。"""

    def collect(self, **kwargs: Any) -> CostLedger:
        ...


@dataclass
class Verdict:
    """准入函数 A(M, S) 的最终输出（对外 API 的形状）。"""

    mod_id: str
    agent_id: str
    round_index: int
    layer: str
    autonomy: str
    risk_index: float
    is_high_risk: bool
    action: AdmissionAction
    gate_level_reached: GateLevel
    results: list[CheckResult] = field(default_factory=list)
    cost: CostLedger = field(default_factory=CostLedger)
    elapsed_s: float = 0.0
    audit_hash: str = ""
    escalations: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# 工具函数
# --------------------------------------------------------------------------


def now() -> float:
    return time.time()


def path_key(layer: Layer, autonomy: Autonomy) -> str:
    """修改路径键：熔断锁定与标定都以它为单位。"""
    return f"{layer.value}×{autonomy.value}"


def stable_id(prefix: str, *parts: Any) -> str:
    blob = "|".join(str(p) for p in parts)
    h = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}-{h}"
