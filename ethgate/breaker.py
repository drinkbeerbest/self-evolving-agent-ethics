"""伦理熔断状态机（开题报告 §3.2.3）。

熔断与拒绝的区别不在处置动作，而在状态：拒绝是一次性的，熔断是有状态的——
它会锁定某类修改路径一段时间，把触发事件送入后续的阈值标定，并把系统
维持在「最近一次通过审查的版本」上（开题报告 §3.2.3 末段）。

四类触发条件（开题报告 §3.2.3）：
  1. INVARIANT_VIOLATION  一级/二级门禁出现 FAIL（不变量违反）
  2. SHADOW_DRIFT         影子期行为偏移超过 config.shadow_drift_threshold
  3. COST_OVER_BUDGET     审查成本超出预算 config.cost_budget_per_mod
  4. EXTERNAL_AUDIT_VETO  外部审计否决（notify_external_veto）

触发后统一执行：锁定 path_key(layer, autonomy) → 记录回滚点 → 写审计链 kind="breaker"。

状态机示意：
    正常 --(触发)--> 锁定(until) --(到期 unlock_expired)--> 正常
"""
from __future__ import annotations

from .audit import AuditChain
from .config import GateConfig
from .types import (
    BreakerEvent,
    BreakerTrigger,
    CheckResult,
    CheckStatus,
    GateResult,
    Modification,
    SystemState,
    now,
    path_key,
    to_jsonable,
)

__all__ = ["CircuitBreaker"]

# 同一进程内，同一审计日志路径只允许存在一个 AuditChain 实例：
# AuditChain.append 每次都会把内存中的全部记录重写回文件，
# 若两个实例指向同一文件，后写入的一方会用自己加载时的旧快照覆盖另一方的新记录。
# 因此这里按路径共享实例，保证「流水线内建的熔断器」与「外部显式传入的熔断器」
# 写入的是同一条链。
_SHARED_AUDIT: dict[str, AuditChain] = {}



class CircuitBreaker:
    """路径锁定的有状态熔断器。"""

    def __init__(self, config: GateConfig, audit: AuditChain | None = None):
        self.config = config
        self._audit = audit
        if audit is not None and config.audit_log:
            # 显式传入的审计链登记为该路径的共享实例
            _SHARED_AUDIT[str(config.audit_log)] = audit
        self._locks: dict[str, dict[str, float]] = {}   # path_key -> {子键: 截止时间}
        self._events: list[BreakerEvent] = []       # 熔断事件历史
        self._last_passed: dict[str, str] = {}      # path_key -> 最近一次通过审查的版本
        self._last_passed_global: str = ""          # 全局最近一次通过审查的版本
        self._mod_paths: dict[str, str] = {}        # mod_id -> path_key
        self._vetoes: dict[str, str] = {}           # mod_id -> 外部否决理由

    # -- 审计链 ---------------------------------------------------------
    @property
    def audit_chain(self) -> AuditChain | None:
        """惰性创建审计链：构造熔断器本身不产生任何磁盘副作用。

        同一路径在进程内共享同一个 AuditChain 实例（见 _SHARED_AUDIT）。
        """
        if self._audit is None and self.config.audit_log:
            key = str(self.config.audit_log)
            chain = _SHARED_AUDIT.get(key)
            if chain is None:
                chain = AuditChain(key)
                _SHARED_AUDIT[key] = chain
            self._audit = chain
        return self._audit

    # -- 触发判定 -------------------------------------------------------
    def evaluate(self, mod: Modification, gate_result: GateResult) -> BreakerEvent | None:
        """根据一次门禁判定结果判定是否触发熔断；不触发时返回 None。"""
        trigger, reason = self._detect(mod, gate_result)
        if trigger is None:
            return None
        return self._trip(mod, trigger, reason, gate_result)

    def _detect(
        self, mod: Modification, gate_result: GateResult
    ) -> tuple[BreakerTrigger | None, str]:
        """按优先级检出第一类触发条件。"""
        # 1) 不变量违反：一级/二级门禁出现 FAIL
        failed = [r for r in gate_result.results if r.status is CheckStatus.FAIL]
        if failed:
            names = "、".join(_result_label(r) for r in failed)
            return BreakerTrigger.INVARIANT_VIOLATION, f"门禁判定失败：{names}"

        # 2) 影子期行为偏移超阈值
        drift = gate_result.detail.get("shadow_drift")
        if drift is not None and float(drift) > float(self.config.shadow_drift_threshold):
            return (
                BreakerTrigger.SHADOW_DRIFT,
                f"影子期行为偏移 {float(drift):.4f} 超过阈值 "
                f"{float(self.config.shadow_drift_threshold):.4f}",
            )

        # 3) 审查成本超预算（相对基线的倍数）
        cost = gate_result.cost
        if cost is not None and float(cost.c_lat) > float(self.config.cost_budget_per_mod):
            return (
                BreakerTrigger.COST_OVER_BUDGET,
                f"审查时延成本 {float(cost.c_lat):.4f} 超出预算 "
                f"{float(self.config.cost_budget_per_mod):.4f}",
            )

        # 4) 外部审计否决（尚未映射到路径时，先登记，等路径可知后再锁定）
        veto = self._vetoes.get(mod.mod_id)
        if veto:
            return BreakerTrigger.EXTERNAL_AUDIT_VETO, f"外部审计否决：{veto}"

        return None, ""

    # -- 熔断动作 -------------------------------------------------------
    def _trip(
        self,
        mod: Modification,
        trigger: BreakerTrigger,
        reason: str,
        gate_result: GateResult | None = None,
    ) -> BreakerEvent:
        """执行熔断：锁定路径、记录回滚点、写审计链。"""
        key = self._path_of(mod)
        if key:
            self._mod_paths[mod.mod_id] = key
        until = now() + float(self.config.lock_duration_s)
        granularity = str(getattr(self.config, "lock_granularity", "path_rule"))
        event = self.lock(
            key,
            until,
            reason,
            trigger=trigger,
            mod_id=mod.mod_id,
            subkey=self._subkey(mod, gate_result),
            do_lock=(granularity != "none"),
        )
        if gate_result is not None:
            event.cost = gate_result.cost
            event.detail["gate_level"] = int(gate_result.level)
            event.detail["gate_action"] = gate_result.action.value
        return event

    def _subkey(self, mod: Modification, gate_result: GateResult | None) -> str:
        """锁定的子键 —— 决定锁定的**粒度**。

        粒度对照（这是本项目实测出来的一个关键工程结论）：

        ``path``
            锁定整条「修改层 × 自主度」路径。一次违规就把这一类修改全部锁死，
            连带效应极强——实测把全流程门禁的误拦率从 4% 抬到 **72%**，
            其中 67 个百分点来自锁定本身而非不变量误判。
            这正是开题报告 §8.2 局限⑤ 所说的"滥用熔断的代价"。

        ``path_rule``（默认）
            锁定「修改层 × 自主度 × 触发不变量」。只有同一类风险模式继续发生
            才会被拦住，同一类的合法修改仍可正常通过。
            机制因此"既有记忆、又不误伤"。

        ``none``
            只记录熔断事件，不锁定路径（用于消融对照）。
        """
        granularity = str(getattr(self.config, "lock_granularity", "path_rule"))
        if granularity == "none":
            return ""
        if granularity != "path_rule":
            return ""
        if gate_result is None:
            return ""
        failed = [r for r in gate_result.results if r.status is CheckStatus.FAIL]
        if failed:
            return "#" + "+".join(sorted({r.invariant for r in failed}))
        drift = gate_result.detail.get("shadow_drift")
        if drift is not None:
            return "#shadow"
        return "#cost"

    def lock(
        self,
        path_key: str,
        until: float,
        reason: str,
        *,
        trigger: BreakerTrigger = BreakerTrigger.INVARIANT_VIOLATION,
        mod_id: str = "",
        subkey: str = "",
        do_lock: bool = True,
    ) -> BreakerEvent:
        """锁定一条修改路径直到 until 时刻，并登记一次熔断事件。"""
        rollback_to = self.rollback_point(path_key)
        event = BreakerEvent(
            trigger=trigger,
            mod_id=mod_id,
            path_key=path_key,
            locked_until=float(until),
            rollback_to=rollback_to,
            action_taken=(
                f"锁定路径「{path_key}{subkey}」至 {float(until):.0f}，"
                f"系统回滚至「{rollback_to or '最近通过版本（未知）'}」"
            ),
            detail={"reason": reason, "subkey": subkey},
        )
        # 已有锁定期更长时不缩短
        if path_key and do_lock:
            bucket = self._locks.setdefault(path_key, {})
            k = subkey or "#all"
            bucket[k] = max(bucket.get(k, 0.0), float(until))
        self._events.append(event)
        self._write_audit(event)
        return event

    def notify_external_veto(self, mod_id: str, reason: str) -> BreakerEvent:
        """登记一次外部审计否决。

        路径已知时立即锁定该路径；路径未知（例如否决先于提案到达）时先登记，
        待路径映射建立后再由 `evaluate` 补锁。
        """
        self._vetoes[mod_id] = reason
        key = self._mod_paths.get(mod_id, "")
        if key:
            return self.lock(
                key,
                now() + float(self.config.lock_duration_s),
                f"外部审计否决：{reason}",
                trigger=BreakerTrigger.EXTERNAL_AUDIT_VETO,
                mod_id=mod_id,
            )
        # 路径未知：只登记事件，不锁定
        event = BreakerEvent(
            trigger=BreakerTrigger.EXTERNAL_AUDIT_VETO,
            mod_id=mod_id,
            path_key="",
            locked_until=0.0,
            rollback_to=self.rollback_point(""),
            action_taken="登记外部审计否决（修改路径未知，待映射后锁定）",
            detail={"reason": reason},
        )
        self._events.append(event)
        self._write_audit(event)
        return event

    def veto_for(self, mod_id: str) -> str | None:
        """查询某次提案是否已被外部否决。"""
        return self._vetoes.get(mod_id)

    # -- 回滚点维护 -----------------------------------------------------
    def record_passed(self, mod: Modification | str, state: SystemState | None = None) -> str:
        """登记「最近一次通过审查的版本」，供熔断时作为回滚点。

        接受 Modification 对象或 mod_id 字符串两种形式：
          * 传入 Modification 时能同时得到修改路径（层 × 自主度），回滚点按路径记录；
          * 只传入 mod_id 时退化为全局回滚点。
        """
        mod_id = getattr(mod, "mod_id", str(mod))
        version = ""
        if state is not None:
            version = getattr(state, "code_version", "") or ""
        if not version:
            version = getattr(mod, "base_commit", "") or ""
        if not version:
            version = mod_id

        key = self._path_of(mod)
        self._last_passed[key] = version
        self._last_passed_global = version
        if key:
            self._mod_paths[mod_id] = key
        return version

    def rollback_point(self, key: str = "") -> str:
        """取回滚点：优先取该路径最近一次通过审查的版本，其次取全局最近版本。"""
        if key and key in self._last_passed:
            return self._last_passed[key]
        return self._last_passed_global

    # -- 查询 -----------------------------------------------------------
    def is_locked(self, mod: Modification) -> bool:
        """该修改路径是否**处于直接拒绝**状态。

        只有粗粒度（``path``）会直接拒绝整条路径上的提案——实测这种连带效应
        会把误拦率从 4% 抬到 72%。细化粒度（``path_rule``）下不直接拒绝，
        而是让该路径强制走完最严门禁（见 `has_active_lock`），
        同一类合法修改因此不受牵连。
        """
        if str(getattr(self.config, "lock_granularity", "path_rule")) != "path":
            return False
        key = self._path_of(mod)
        if not key:
            return False
        bucket = self._locks.get(key) or {}
        t = now()
        return any(v > t for v in bucket.values())

    def has_active_lock(self, mod: Modification) -> bool:
        """该修改路径上是否存在仍然有效的熔断锁定（任意粒度）。

        细化粒度下用它来决定"是否强制走最严门禁"，而不是直接拒绝。
        """
        key = self._path_of(mod)
        if not key:
            return False
        bucket = self._locks.get(key) or {}
        t = now()
        return any(v > t for v in bucket.values())

    def locked_rules(self, mod: Modification) -> dict[str, float]:
        """该修改路径上的锁定子键 → 截止时间。"""
        key = self._path_of(mod)
        return dict(self._locks.get(key) or {}) if key else {}

    def locked_paths(self) -> dict[str, float]:
        """当前所有被锁定的路径及其截止时间（取各子键的最大值）。"""
        return {k: max(v.values()) for k, v in self._locks.items() if v}

    def locked_detail(self) -> dict[str, dict[str, float]]:
        """锁定的完整视图：路径 → {子键: 截止时间}。"""
        return {k: dict(v) for k, v in self._locks.items() if v}

    def history(self) -> list[BreakerEvent]:
        """熔断事件历史。"""
        return list(self._events)

    def unlock_expired(self) -> list[str]:
        """释放所有已过期的锁，返回被释放的路径键列表。"""
        t = now()
        expired: list[str] = []
        for k in list(self._locks):
            bucket = self._locks[k]
            for sk in list(bucket):
                if bucket[sk] <= t:
                    del bucket[sk]
            if not bucket:
                del self._locks[k]
                expired.append(k)
        return expired

    def unlock(self, path_key: str, reason: str = "人工解除熔断锁定") -> bool:
        """人工解除某条路径的锁定。

        熔断是有状态的，因此解除也必须是显式动作并留下审计痕迹——
        这对应开题报告"规则公开、拒绝理由可申诉"的制度要求。
        """
        if path_key not in self._locks:
            return False
        del self._locks[path_key]
        event = BreakerEvent(
            trigger=BreakerTrigger.EXTERNAL_AUDIT_VETO,
            path_key=path_key,
            action_taken=f"人工解除路径「{path_key}」的熔断锁定",
            detail={"reason": reason, "manual": True},
        )
        self._events.append(event)
        self._write_audit(event)
        return True

    # -- 内部 -----------------------------------------------------------
    def _path_of(self, mod: Modification | str) -> str:
        """取修改路径键；只有字符串（mod_id）时返回空串。"""
        layer = getattr(mod, "layer", None)
        autonomy = getattr(mod, "autonomy", None)
        if layer is None or autonomy is None:
            return ""
        return path_key(layer, autonomy)

    def _lock_until(self, key: str) -> float:
        return float(self._locks.get(key, 0.0))

    def _write_audit(self, event: BreakerEvent) -> None:
        """把熔断事件写入哈希链审计日志（I2 审计完备性）。"""
        chain = self.audit_chain
        if chain is None:
            return
        payload = to_jsonable(
            {
                "event_id": event.event_id,
                "trigger": event.trigger,
                "mod_id": event.mod_id,
                "path_key": event.path_key,
                "locked_until": event.locked_until,
                "rollback_to": event.rollback_to,
                "action_taken": event.action_taken,
                "detail": event.detail,
            }
        )
        chain.append("breaker", payload)


def _result_label(result: CheckResult) -> str:
    """给一条检查结果生成可读标签。"""
    inv = str(result.invariant or "?").upper()
    summary = (result.summary or "").strip()
    return f"{inv}({summary})" if summary else inv
