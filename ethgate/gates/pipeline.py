"""四级门禁流水线（开题报告 §3.2.3）。

准入判定不是一个开关，而是一组逐级加严的关卡（开题报告 图3）：
每一级有独立的通过条件与成本，前一级不通过则不进入下一级。

    一级 静态审查  I1~I4 形式化检查 + 高危格判定      毫秒级
    二级 沙箱演练  回归测试 + 越权探测 + 强制中断        分钟级
    三级 影子模式  修改前后行为分布对比                  小时到天级（可跳过）
    四级 灰度放量  分级放开 + 观察窗 + 回滚              天级

流水线语义（与 CONTRACT「任务 B」一致）：

  * 一级返回 ESCALATE / REJECT → 立即中止，不再进入下一级；
  * 一级返回 SANDBOX → 该提案必须进入二级（高危格强制加严或判定不确定）；
  * 其余情况逐级上行，直到 `config.max_gate_level` 指定的最高级别；
  * 熔断前置检查：路径已锁定 或 已被外部审计否决 → 直接 REJECT；
  * 判定结束后调用 `CircuitBreaker.evaluate` 判定是否触发熔断，并写审计链。

对 `ethgate.invariants` 的导入是**延迟导入**（见 static.py），保证本模块
在并行任务尚未完成时也能独立 import 与运行。
"""
from __future__ import annotations

import time
from typing import Any, Sequence

from ..breaker import CircuitBreaker
from ..config import GateConfig
from ..cost import CostCollector
from ..taxonomy import RiskCell, build_matrix, find_cell
from ..types import (
    AdmissionAction,
    BreakerTrigger,
    CheckResult,
    CheckStatus,
    GateLevel,
    GateResult,
    Layer,
    Modification,
    SystemState,
    path_key,
    to_jsonable,
)
from .canary import build_canary_plan
from .sandbox import SandboxSuite
from .shadow import BehaviorProbe, compute_drift, default_behavior_probe
from .static import normalize_invariant, run_static_checks

__all__ = ["GatePipeline"]

# 各级的 detail 透传到顶层时保留的字段
_PASSTHROUGH_KEYS = (
    "escalate_to",
    "risk_index",
    "is_high_risk",
    "cell_key",
    "shadow_drift",
    "shadow_threshold",
    "traffic_ratio",
    "observation_window_s",
    "rollback_point",
    "canary_stages",
)


class GatePipeline:
    """四级门禁流水线。

    参数
      config  门禁配置（阈值、开关、预算、锁定时长）
      cells   18 格风险矩阵；为 None 时按 config.high_risk_threshold 现算
      breaker 可选：复用外部已有的熔断器（默认自建一个）

    可替换的注入点（便于测试与替换真实基础设施）：
      pipeline.checkers      静态检查器列表（None → ethgate.invariants 默认）
      pipeline.sandbox       SandboxSuite 实例
      pipeline.behavior_probe 影子期行为度量函数
      pipeline.breaker       CircuitBreaker 实例
    """

    def __init__(
        self,
        config: GateConfig,
        cells: list[RiskCell] | None = None,
        *,
        breaker: CircuitBreaker | None = None,
    ):
        self.config = config
        self.cells: list[RiskCell] = (
            list(cells)
            if cells is not None
            else build_matrix(high_risk_threshold=config.high_risk_threshold)
        )
        self.breaker = breaker if breaker is not None else CircuitBreaker(config)
        self.cost_collector = CostCollector(config)
        self._sandbox_suite = SandboxSuite()
        self.behavior_probe: BehaviorProbe = default_behavior_probe
        self.checkers: Sequence[Any] | None = None
        self.canary_stages: Sequence[float] | None = None
        self.observation_window_s: float | None = None
        # 基线时延：无门禁时单次修改的耗时；有值时才能算出 c_lat
        self.baseline_elapsed_s: float | None = None

    # -- 注入点 ---------------------------------------------------------
    @property
    def sandbox(self) -> SandboxSuite:
        """沙箱测试集（可替换为注入桩）。"""
        return self._sandbox_suite

    @sandbox.setter
    def sandbox(self, suite: SandboxSuite) -> None:
        self._sandbox_suite = suite

    # -- 查询 -----------------------------------------------------------
    def risk_of(self, mod: Modification) -> RiskCell | None:
        """取该提案所属分类格（层 × 自主度）的风险刻画。"""
        return find_cell(mod.layer, mod.autonomy, self.cells)

    # ==================================================================
    # 主流程
    # ==================================================================
    def run(self, mod: Modification, state: SystemState) -> GateResult:
        """跑完整的四级门禁流水线，返回最终判定。"""
        t0 = time.time()
        results: list[CheckResult] = []
        detail: dict[str, Any] = {
            "mod_id": mod.mod_id,
            "path_key": path_key(mod.layer, mod.autonomy),
            "trace": [],
        }

        # -- 0) 熔断前置检查：外部否决 / 路径已锁定 --------------------
        veto = self.breaker.veto_for(mod.mod_id)
        if veto:
            detail.update({"reason": "外部审计否决", "veto_reason": veto})
            return self._finalize(
                mod,
                state,
                GateResult(
                    level=GateLevel.STATIC,
                    action=AdmissionAction.REJECT,
                    results=results,
                    detail=detail,
                ),
                t0,
            )
        if self.breaker.is_locked(mod):
            key = detail["path_key"]
            detail.update(
                {
                    "reason": "路径已锁定",
                    "locked": True,
                    "locked_until": self.breaker.locked_paths().get(key, 0.0),
                }
            )
            return self._finalize(
                mod,
                state,
                GateResult(
                    level=GateLevel.STATIC,
                    action=AdmissionAction.REJECT,
                    results=results,
                    detail=detail,
                ),
                t0,
            )

        # -- 1) 一级：静态审查 ------------------------------------------
        static_res = self._static(mod, state)
        self._absorb("static", static_res, results, detail)
        if static_res.action in (AdmissionAction.ESCALATE, AdmissionAction.REJECT):
            return self._finalize(
                mod,
                state,
                GateResult(
                    level=GateLevel.STATIC,
                    action=static_res.action,
                    results=results,
                    detail=detail,
                ),
                t0,
            )

        max_level = int(self.config.max_gate_level)
        required = int(detail.get("escalate_to", GateLevel.STATIC))
        # 细化粒度下，路径上的熔断锁定不直接拒绝提案，而是**强制走完最严门禁**：
        # 该路径已被证明出过问题，后续同类修改必须经过全部四级审查才准生效，
        # 但同一类的合法修改不会因为"曾经出过事"而被连带挡下。
        if self.breaker.has_active_lock(mod):
            required = max(required, max_level)
            detail["locked_path"] = detail.get("path_key", "")
            detail["locked_rules"] = self.breaker.locked_rules(mod)
            detail["reason_locked"] = (
                "该修改路径存在有效的熔断锁定，强制升级至最严门禁（第 "
                f"{max_level} 级）后方可生效"
            )
        if max_level < required:
            # 应进入的门禁级高于配置上限：不能静默放行，交给人工裁决
            detail.update(
                {
                    "reason": (
                        f"应进入的第 {required} 级门禁高于配置上限 "
                        f"max_gate_level={max_level}，上报人工裁决"
                    )
                }
            )
            return self._finalize(
                mod,
                state,
                GateResult(
                    level=GateLevel.STATIC,
                    action=AdmissionAction.ESCALATE,
                    results=results,
                    detail=detail,
                ),
                t0,
            )

        level = GateLevel.STATIC
        action = static_res.action

        # -- 2) 二级：沙箱演练 ------------------------------------------
        if max_level >= int(GateLevel.SANDBOX):
            sandbox_res = self._sandbox(mod, state)
            self._absorb("sandbox", sandbox_res, results, detail)
            if sandbox_res.action is AdmissionAction.REJECT:
                return self._finalize(
                    mod,
                    state,
                    GateResult(
                        level=GateLevel.SANDBOX,
                        action=AdmissionAction.REJECT,
                        results=results,
                        detail=detail,
                    ),
                    t0,
                )
            level = GateLevel.SANDBOX
            action = AdmissionAction.PASS

        # -- 3) 三级：影子模式 ------------------------------------------
        if max_level >= int(GateLevel.SHADOW):
            shadow_res = self._shadow(mod, state)
            self._absorb("shadow", shadow_res, results, detail)
            if shadow_res.action is AdmissionAction.ESCALATE:
                return self._finalize(
                    mod,
                    state,
                    GateResult(
                        level=GateLevel.SHADOW,
                        action=AdmissionAction.ESCALATE,
                        results=results,
                        detail=detail,
                    ),
                    t0,
                )
            level = GateLevel.SHADOW
            action = AdmissionAction.PASS

        # -- 4) 四级：灰度放量 ------------------------------------------
        if max_level >= int(GateLevel.CANARY):
            canary_res = self._canary(mod, state)
            self._absorb("canary", canary_res, results, detail)
            level = GateLevel.CANARY
        action = AdmissionAction.PASS

        return self._finalize(
            mod,
            state,
            GateResult(
                level=level,
                action=action,
                results=results,
                detail=detail,
            ),
            t0,
        )

    # ==================================================================
    # 各级门禁
    # ==================================================================
    def _static(self, mod: Modification, state: SystemState) -> GateResult:
        """一级门禁：静态审查（I1~I4 + 高危格判定）。"""
        t0 = time.time()
        results = run_static_checks(mod, state, self.config, self.checkers)

        cell = self.risk_of(mod)
        high_risk = bool(cell.is_high_risk) if cell is not None else False

        failed = [r for r in results if r.status is CheckStatus.FAIL]
        uncertain = [r for r in results if r.status is CheckStatus.UNCERTAIN]

        detail: dict[str, Any] = {
            "failed_invariants": [r.invariant for r in failed],
            "uncertain_invariants": [r.invariant for r in uncertain],
            "risk_index": round(float(cell.risk_index), 4) if cell is not None else None,
            "is_high_risk": high_risk,
            "cell_key": cell.key if cell is not None else "",
        }

        if failed:
            # 约束层改写约束且违反 I4 → 直接拒绝；其余 FAIL → 上报人工裁决
            i4_broken = any(normalize_invariant(r.invariant) == "I4" for r in failed)
            if mod.layer is Layer.CONSTRAINT and i4_broken:
                action = AdmissionAction.REJECT
                detail["reason"] = "约束层改写违反 I4 约束守恒，直接拒绝"
            else:
                action = AdmissionAction.ESCALATE
                detail["reason"] = "静态检查发现不变量违反，上报人工裁决"
            detail["escalate_to_human"] = True
            detail["escalate_to"] = GateLevel.STATIC
        elif uncertain:
            action = AdmissionAction.SANDBOX
            detail["reason"] = "静态检查存在不确定判定，转入沙箱演练"
            detail["escalate_to"] = GateLevel.SANDBOX
        elif high_risk:
            action = AdmissionAction.SANDBOX
            detail["reason"] = "提案落在高危格，强制加严至沙箱演练"
            detail["escalate_to"] = GateLevel.SANDBOX
        else:
            action = AdmissionAction.PASS
            detail["reason"] = "静态检查全部通过且非高危格"
            detail["escalate_to"] = GateLevel.STATIC

        return GateResult(
            level=GateLevel.STATIC,
            action=action,
            results=results,
            elapsed_s=time.time() - t0,
            detail=detail,
        )

    def _sandbox(self, mod: Modification, state: SystemState) -> GateResult:
        """二级门禁：沙箱演练（回归 + 越权探测 + 强制中断 + 日志完整性）。"""
        t0 = time.time()
        results = self._sandbox_suite.run(mod, state)
        failed = [r for r in results if r.status is CheckStatus.FAIL]
        action = AdmissionAction.REJECT if failed else AdmissionAction.PASS
        detail = {
            "sandbox_cases": len(results),
            "sandbox_failed": [r.summary for r in failed],
            "reason": (
                "沙箱演练失败：" + "、".join(r.summary for r in failed)
                if failed
                else "沙箱演练全部用例通过"
            ),
        }
        return GateResult(
            level=GateLevel.SANDBOX,
            action=action,
            results=results,
            elapsed_s=time.time() - t0,
            detail=detail,
        )

    def _shadow(self, mod: Modification, state: SystemState) -> GateResult:
        """三级门禁：影子模式（行为分布偏移检测）。"""
        t0 = time.time()
        threshold = float(self.config.shadow_drift_threshold)
        try:
            metrics = self.behavior_probe(mod, state) or {}
            if not isinstance(metrics, dict):
                raise TypeError(
                    f"behavior_probe 必须返回 dict，实际返回 {type(metrics).__name__}"
                )
        except Exception as exc:
            # 影子期无法度量 → 无法证明安全，转人工裁决
            detail = {
                "shadow_drift": 1.0,
                "shadow_threshold": threshold,
                "shadow_metrics": {},
                "reason": f"影子期行为度量失败：{type(exc).__name__}: {exc}",
            }
            return GateResult(
                level=GateLevel.SHADOW,
                action=AdmissionAction.ESCALATE,
                results=[],
                elapsed_s=time.time() - t0,
                detail=detail,
            )

        drift = compute_drift(metrics)
        action = (
            AdmissionAction.ESCALATE if drift > threshold else AdmissionAction.PASS
        )
        detail = {
            "shadow_drift": drift,
            "shadow_threshold": threshold,
            "shadow_metrics": dict(metrics),
            "reason": (
                f"影子期行为偏移 {drift:.4f} 超过阈值 {threshold:.4f}，上报人工裁决"
                if action is AdmissionAction.ESCALATE
                else f"影子期行为偏移 {drift:.4f} 未超过阈值 {threshold:.4f}"
            ),
        }
        return GateResult(
            level=GateLevel.SHADOW,
            action=action,
            results=[],
            elapsed_s=time.time() - t0,
            detail=detail,
        )

    def _canary(self, mod: Modification, state: SystemState) -> GateResult:
        """四级门禁：灰度放量（记录放量计划、观察窗与回滚点）。"""
        t0 = time.time()
        key = path_key(mod.layer, mod.autonomy)
        plan = build_canary_plan(
            mod,
            state,
            stages=self.canary_stages,
            observation_window_s=self.observation_window_s,
            rollback_point=self.breaker.rollback_point(key) or None,
            drift_threshold=float(self.config.shadow_drift_threshold),
        )
        plan["reason"] = "灰度计划已登记，进入分级放量与观察窗"
        return GateResult(
            level=GateLevel.CANARY,
            action=AdmissionAction.PASS,
            results=[],
            elapsed_s=time.time() - t0,
            detail=plan,
        )

    # ==================================================================
    # 收尾：成本账、熔断判定、审计
    # ==================================================================
    def _absorb(
        self,
        name: str,
        res: GateResult,
        results: list[CheckResult],
        detail: dict[str, Any],
    ) -> None:
        """把一级的结果并入总账。"""
        results.extend(res.results)
        detail[name] = dict(res.detail)
        for key in _PASSTHROUGH_KEYS:
            if key in res.detail:
                detail[key] = res.detail[key]
        # 终止流水线的级别决定最终理由（通过时不覆盖）
        if res.action is not AdmissionAction.PASS and "reason" in res.detail:
            detail["reason"] = res.detail["reason"]
        detail["trace"].append(
            {
                "gate": name,
                "level": int(res.level),
                "action": res.action.value,
                "elapsed_s": round(float(res.elapsed_s), 6),
            }
        )

    def _finalize(
        self,
        mod: Modification,
        state: SystemState,
        res: GateResult,
        t0: float,
    ) -> GateResult:
        """结算：耗时、成本账、熔断判定、审计记录、回滚点维护。"""
        res.elapsed_s = time.time() - t0
        if res.cost is None:
            # 把本次判定的实际开销喂给成本采集器。
            # c_lat 等比值需要"无门禁基线"才有意义，单次判定时留 0，
            # 但**绝对开销必须记下来**——否则界面上看不到"这次审查花了多少钱"，
            # 成本与判定同屏这个设计点就落空了。
            res.cost = self.cost_collector.collect(
                elapsed_s=res.elapsed_s,
                tokens=float(res.detail.get("tokens", 0.0) or 0.0),
                gpu_s=float(res.detail.get("gpu_s", 0.0) or 0.0),
            )
        res.detail["cost_absolute"] = {
            "elapsed_s": round(res.elapsed_s, 6),
            "tokens": float(res.detail.get("tokens", 0.0) or 0.0),
            "gpu_s": float(res.detail.get("gpu_s", 0.0) or 0.0),
            "comp_cost": round(res.cost.c_comp, 6),
        }
        if self.baseline_elapsed_s:
            res.cost.c_lat = res.elapsed_s / float(self.baseline_elapsed_s)
        else:
            res.detail.setdefault(
                "cost_note",
                "缺少无门禁基线时延，c_lat 记 0.0（不可测量不等于零成本）；"
                "绝对开销见 cost_absolute",
            )

        # 熔断判定：不变量违反 / 影子偏移 / 成本超预算 / 外部否决
        event = self.breaker.evaluate(mod, res)
        if event is not None:
            res.detail["breaker"] = to_jsonable(event)
            res.detail["breaker_trigger"] = event.trigger.value
            res.detail["locked_path"] = event.path_key
            if (
                event.trigger is BreakerTrigger.COST_OVER_BUDGET
                and res.action is AdmissionAction.PASS
            ):
                # 成本超预算不应被静默放行：转人工裁决
                res.action = AdmissionAction.ESCALATE
                res.detail["reason"] = "审查成本超出预算，熔断并上报人工裁决"

        if res.action is AdmissionAction.PASS:
            res.detail["reason"] = (
                f"通过第 {int(res.level)} 级门禁，未触发熔断条件"
            )
            # 通过审查 → 维护回滚点（最近一次通过审查的版本）
            res.detail["rollback_point"] = self.breaker.record_passed(mod, state)

        self._write_audit(mod, res)
        return res

    def _write_audit(self, mod: Modification, res: GateResult) -> None:
        """把判定结果写入哈希链审计日志（I2 审计完备性）。"""
        chain = self.breaker.audit_chain
        if chain is None:
            return
        payload = to_jsonable(
            {
                "mod_id": mod.mod_id,
                "agent_id": mod.agent_id,
                "layer": mod.layer,
                "autonomy": mod.autonomy,
                "action": res.action,
                "level": int(res.level),
                "results": res.results,
                "cost": res.cost.as_dict(),
                "elapsed_s": res.elapsed_s,
                "detail": res.detail,
            }
        )
        chain.append("verdict", payload)
        if res.action is AdmissionAction.ESCALATE:
            chain.append(
                "escalate",
                to_jsonable(
                    {
                        "mod_id": mod.mod_id,
                        "level": int(res.level),
                        "reason": res.detail.get("reason", ""),
                    }
                ),
            )
