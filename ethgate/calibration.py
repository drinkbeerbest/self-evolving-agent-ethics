"""熔断阈值的自适应标定（开题报告 §3.4「熔断阈值的自适应标定」）。

标定问题
--------
    min_θ C_ali(θ)    s.t.   FNR(θ) ≤ ε,  FPR(θ) ≤ δ

θ 是门禁严格度（控制量），FNR 是漏放率（受控量），ε 是风险预算，δ 是可用性预算。

实现要点
--------
* **不使用 scipy**：高斯过程代理（RBF 核 + Cholesky 分解）、期望改进（EI）采集函数、
  约束可行概率全部用 numpy 自研。
* **约束不可行时不放宽约束**：返回 ``{"feasible": False, "escalate": True, ...}``，
  对应"自动提升门禁等级并报警，把决策权交回人类"这条降级路径（§3.4 末段）。
* **非平稳性**：`simulate_problem` 造出"能力增长 → 行为分布基线漂移"的问题，
  可复现"固定阈值在漂移后失准"的结论。

跨任务依赖：无（仅依赖 numpy 与标准库）。
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Sequence

import numpy as np

__all__ = [
    "CalibrationProblem",
    "EmpiricalCalibrationProblem",
    "simulate_problem",
    "calibrate",
    "calibrate_on_records",
    "evaluate_fixed_threshold",
    "GaussianProcess",
]


# --------------------------------------------------------------------------
# 高斯过程（numpy 自研）
# --------------------------------------------------------------------------


class GaussianProcess:
    """一维高斯过程回归：RBF 核 + Cholesky 分解。

    仅依赖 numpy：核矩阵手工构造，Cholesky 用 numpy.linalg.cholesky，
    数值不稳时自动增加 nugget 后重试。
    """

    def __init__(
        self,
        lengthscale: float = 0.18,
        signal: float = 1.0,
        noise: float = 1e-4,
    ):
        self.lengthscale = float(lengthscale)
        self.signal = float(signal)
        self.noise = float(noise)
        self.X: np.ndarray | None = None
        self.L: np.ndarray | None = None
        self.alpha: np.ndarray | None = None
        self.y_mean = 0.0
        self.y_std = 1.0

    # -- 核 --------------------------------------------------------------
    def _kernel(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        d = a.reshape(-1, 1) - b.reshape(1, -1)
        return self.signal**2 * np.exp(-0.5 * (d / self.lengthscale) ** 2)

    # -- 拟合 ------------------------------------------------------------
    def fit(self, X: Sequence[float], y: Sequence[float]) -> "GaussianProcess":
        X = np.asarray(X, dtype=float).reshape(-1, 1)
        y = np.asarray(y, dtype=float).reshape(-1)
        self.X = X
        self.y_mean = float(y.mean()) if len(y) else 0.0
        std = float(y.std())
        self.y_std = std if std > 1e-12 else 1.0
        ys = (y - self.y_mean) / self.y_std
        K = self._kernel(X, X)
        n = K.shape[0]
        jitter = self.noise
        L = None
        for _ in range(6):
            try:
                L = np.linalg.cholesky(K + (jitter + 1e-10) * np.eye(n))
                break
            except np.linalg.LinAlgError:
                jitter = jitter * 10 if jitter > 0 else 1e-6
                jitter = max(jitter, 1e-8)
        if L is None:  # pragma: no cover - 极端数值情况
            L = np.linalg.cholesky(K + 1e-3 * np.eye(n))
        self.L = L
        self.alpha = np.linalg.solve(L.T, np.linalg.solve(L, ys))
        return self

    # -- 预测 ------------------------------------------------------------
    def predict(self, Xs: Sequence[float]) -> tuple[np.ndarray, np.ndarray]:
        assert self.X is not None and self.L is not None, "GP 尚未拟合"
        Xs = np.asarray(Xs, dtype=float).reshape(-1, 1)
        Ks = self._kernel(self.X, Xs)
        mu = Ks.T @ self.alpha
        v = np.linalg.solve(self.L, Ks)
        var = self.signal**2 - np.sum(v**2, axis=0)
        var = np.maximum(var, 1e-12)
        sd = np.sqrt(var)
        return self.y_mean + self.y_std * mu, self.y_std * sd


def _norm_cdf(z: np.ndarray) -> np.ndarray:
    """标准正态 CDF（用 math.erf 实现，避免引入 scipy）。"""
    erf = np.vectorize(math.erf, otypes=[float])
    return 0.5 * (1.0 + erf(np.asarray(z, dtype=float) / math.sqrt(2.0)))


def _norm_pdf(z: np.ndarray) -> np.ndarray:
    z = np.asarray(z, dtype=float)
    return np.exp(-0.5 * z**2) / math.sqrt(2.0 * math.pi)


def _expected_improvement(
    mu: np.ndarray, sd: np.ndarray, best: float, xi: float = 0.0
) -> np.ndarray:
    """最小化方向的期望改进 EI（越大越好）。"""
    sd = np.maximum(np.asarray(sd, dtype=float), 1e-12)
    mu = np.asarray(mu, dtype=float)
    z = (best - mu - xi) / sd
    ei = (best - mu - xi) * _norm_cdf(z) + sd * _norm_pdf(z)
    return np.maximum(ei, 0.0)


# --------------------------------------------------------------------------
# 标定问题
# --------------------------------------------------------------------------

#: 仿真问题的默认参数
DEFAULT_PARAMS: dict[str, float] = {
    "fnr_a": 0.50,        # θ=0 时的漏放率（最松）
    "fnr_k": 6.00,        # 漏放率随严格度衰减的速率
    "fpr_a": 0.015,       # θ=0 时的误拦率
    "fpr_k": 2.80,        # 误拦率随严格度增长的速率
    "cost_c0": 0.10,      # 成本常数项
    "cost_c1": 0.55,      # 成本线性项
    "cost_c2": 0.25,      # 成本二次项
    "drift_fnr_gain": 0.50,  # 漂移对漏放率的抬升
    "drift_fpr_gain": 0.35,  # 漂移对误拦率的抬升
    "perturb": 0.006,     # 观测扰动幅度（模拟测量噪声）
}


@dataclass
class CalibrationProblem:
    """标定问题：给定严格度 θ 返回目标、漏放率与误拦率。

    `simulate_problem` 返回本类的实例（非平稳仿真问题）。
    """

    kind: str = "simulated"
    seed: int = 0
    drift: float = 0.0
    theta_min: float = 0.0
    theta_max: float = 1.0
    params: dict[str, Any] = field(default_factory=dict)

    # -- 内部 ------------------------------------------------------------
    def _p(self) -> dict[str, float]:
        p = dict(DEFAULT_PARAMS)
        p.update(self.params or {})
        return p

    def _t(self, theta: float) -> float:
        span = self.theta_max - self.theta_min
        if span <= 0:
            return 0.0
        return min(1.0, max(0.0, (float(theta) - self.theta_min) / span))

    def _perturbation(self, t: float) -> tuple[float, float]:
        """种子相关的确定性观测偏移。

        只用"常数 + 极小线性项"，**不引入正弦扰动**：FNR/FPR 的基础曲线
        在严格度高端已经很平（导数趋近 0），任何高频扰动都会破坏契约要求的
        "FNR 随 θ 递减、FPR 随 θ 递增"的单调性。常数偏移不改变导数，
        线性项的斜率被限制在基础曲线导数量级以下，故单调性严格保持。
        """
        p = self._p()
        amp = float(p.get("perturb", 0.0))
        if amp <= 0:
            return 0.0, 0.0
        rng = random.Random(self.seed)
        c1 = rng.uniform(-1.0, 1.0)
        c2 = rng.uniform(-1.0, 1.0)
        c3 = rng.uniform(-1.0, 1.0)
        c4 = rng.uniform(-1.0, 1.0)
        # 线性项斜率上限 0.1 × amp，远小于基础曲线的导数
        return amp * (c1 + 0.1 * c2 * t), amp * (c3 + 0.1 * c4 * t)

    # -- 对外接口 --------------------------------------------------------
    def fnr(self, theta: float) -> float:
        """漏放率：随严格度递减，并随基线漂移整体抬升。"""
        p = self._p()
        t = self._t(theta)
        base = p["fnr_a"] * math.exp(-p["fnr_k"] * t)
        drift = self.drift * p["drift_fnr_gain"] * (0.35 + 0.65 * t)
        pert, _ = self._perturbation(t)
        return min(1.0, max(0.0, base + drift + pert))

    def fpr(self, theta: float) -> float:
        """误拦率：随严格度递增，并随基线漂移整体抬升。"""
        p = self._p()
        t = self._t(theta)
        base = p["fpr_a"] * math.exp(p["fpr_k"] * t)
        drift = self.drift * p["drift_fpr_gain"] * (0.5 + 0.5 * t)
        _, pert = self._perturbation(t)
        return min(1.0, max(0.0, base + drift + pert))

    def objective(self, theta: float) -> float:
        """对齐总成本 C_ali(θ)：随严格度单调递增。"""
        p = self._p()
        t = self._t(theta)
        return p["cost_c0"] + p["cost_c1"] * t + p["cost_c2"] * t * t

    # -- 便利方法 --------------------------------------------------------
    def drifted(self, drift: float) -> "CalibrationProblem":
        """返回同一问题在给定漂移量下的副本（模拟能力增长后的基线漂移）。"""
        return CalibrationProblem(
            kind=self.kind,
            seed=self.seed,
            drift=float(drift),
            theta_min=self.theta_min,
            theta_max=self.theta_max,
            params=dict(self.params or {}),
        )

    def describe(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "seed": self.seed,
            "drift": self.drift,
            "theta_min": self.theta_min,
            "theta_max": self.theta_max,
            "params": self._p(),
        }


@dataclass
class EmpiricalCalibrationProblem(CalibrationProblem):
    """由实验记录构造的经验标定问题（按严格度分组统计 FNR/FPR）。

    组间用线性插值，组外取端点值（保守）。
    """

    groups: list[dict[str, Any]] = field(default_factory=list)

    def _interp(self, theta: float, key: str, default: float) -> float:
        if not self.groups:
            return default
        xs = [float(g["strictness"]) for g in self.groups]
        ys = [float(g.get(key, default)) for g in self.groups]
        return float(np.interp(float(theta), xs, ys))

    def fnr(self, theta: float) -> float:
        return min(1.0, max(0.0, self._interp(theta, "fnr", 1.0)))

    def fpr(self, theta: float) -> float:
        return min(1.0, max(0.0, self._interp(theta, "fpr", 0.0)))

    def objective(self, theta: float) -> float:
        return max(0.0, self._interp(theta, "cost", 0.0))

    def describe(self) -> dict[str, Any]:
        d = super().describe()
        d["groups"] = self.groups
        return d


def simulate_problem(seed: int = 0, drift: float = 0.0) -> CalibrationProblem:
    """构造非平稳的标定问题（模拟自进化系统能力增长导致的基线漂移）。

    * FNR(θ) 随 θ 递减（门禁越严漏放越少），并随漂移整体抬升；
    * FPR(θ) 随 θ 递增（门禁越严误拦越多），并随漂移整体抬升；
    * C_ali(θ) 单调递增（越严越贵）。

    于是：**在漂移前标定出的固定阈值，漂移后同时违反两个约束**，
    这就是"固定阈值在漂移后失准"的结论。
    """
    return CalibrationProblem(
        kind="simulated", seed=int(seed), drift=float(drift),
        theta_min=0.0, theta_max=1.0, params=dict(DEFAULT_PARAMS),
    )


def evaluate_fixed_threshold(
    problem: CalibrationProblem, theta: float, fnr_max: float, fpr_max: float
) -> dict[str, Any]:
    """在给定阈值上检查约束是否仍然成立（用于复现"漂移后失准"）。"""
    fnr = problem.fnr(theta)
    fpr = problem.fpr(theta)
    return {
        "theta": float(theta),
        "fnr": fnr,
        "fpr": fpr,
        "fnr_max": fnr_max,
        "fpr_max": fpr_max,
        "feasible": bool(fnr <= fnr_max and fpr <= fpr_max),
        "fnr_violation": max(0.0, fnr - fnr_max),
        "fpr_violation": max(0.0, fpr - fpr_max),
    }


# --------------------------------------------------------------------------
# 带约束的贝叶斯优化
# --------------------------------------------------------------------------


def calibrate(
    problem: CalibrationProblem,
    fnr_max: float,
    fpr_max: float,
    iterations: int = 60,
    seed: int = 0,
) -> dict[str, Any]:
    """求解 min C_ali(θ) s.t. FNR(θ) ≤ fnr_max, FPR(θ) ≤ fpr_max。

    算法：结构化初始设计 → 高斯过程代理（RBF + Cholesky）→ EI × 可行概率采集函数
    → 逐轮更新。**约束不可行时绝不放宽约束**，而是返回 escalate=True，
    表示应自动提升门禁等级并报警，把决策权交回人类。
    """
    rng = random.Random(seed)
    lo, hi = float(problem.theta_min), float(problem.theta_max)
    if hi <= lo:
        hi = lo + 1.0

    trace: list[dict[str, Any]] = []
    xs: list[float] = []
    objs: list[float] = []
    fnrs: list[float] = []
    fprs: list[float] = []

    def observe(theta: float) -> dict[str, Any]:
        obj = float(problem.objective(theta))
        fnr = float(problem.fnr(theta))
        fpr = float(problem.fpr(theta))
        feasible = bool(fnr <= fnr_max and fpr <= fpr_max)
        xs.append(float(theta))
        objs.append(obj)
        fnrs.append(fnr)
        fprs.append(fpr)
        return {
            "theta": float(theta),
            "objective": obj,
            "fnr": fnr,
            "fpr": fpr,
            "feasible": feasible,
        }

    def best_feasible() -> dict[str, Any] | None:
        cand = [
            (o, x, f, p)
            for x, o, f, p in zip(xs, objs, fnrs, fprs)
            if f <= fnr_max and p <= fpr_max
        ]
        if not cand:
            return None
        o, x, f, p = min(cand, key=lambda t: (t[0], t[1]))
        return {"theta": x, "objective": o, "fnr": f, "fpr": p}

    # -- 初始设计：结构化网格（1 维 BO 的标准做法，保证可行区间被覆盖） ----
    n_init = max(5, min(9, iterations // 4 + 3))
    for i in range(n_init):
        theta = lo + (hi - lo) * (i / (n_init - 1))
        rec = observe(theta)
        bf = best_feasible()
        rec.update(
            {
                "iter": len(trace),
                "stage": "init",
                "best_theta": bf["theta"] if bf else None,
                "best_objective": bf["objective"] if bf else None,
            }
        )
        trace.append(rec)

    # -- 贝叶斯优化主循环 ------------------------------------------------
    grid = np.linspace(lo, hi, 256)
    for step in range(max(0, int(iterations))):
        gp_obj = GaussianProcess(lengthscale=0.18, signal=1.0, noise=1e-4)
        gp_obj.fit(xs, objs)
        gp_fnr = GaussianProcess(lengthscale=0.18, signal=1.0, noise=1e-4)
        gp_fnr.fit(xs, [f - fnr_max for f in fnrs])
        gp_fpr = GaussianProcess(lengthscale=0.18, signal=1.0, noise=1e-4)
        gp_fpr.fit(xs, [p - fpr_max for p in fprs])

        mu, sd = gp_obj.predict(grid)
        bf = best_feasible()
        incumbent = bf["objective"] if bf else min(objs)
        ei = _expected_improvement(mu, sd, incumbent)

        mu_v1, sd_v1 = gp_fnr.predict(grid)
        mu_v2, sd_v2 = gp_fpr.predict(grid)
        p1 = _norm_cdf(-mu_v1 / np.maximum(sd_v1, 1e-9))
        p2 = _norm_cdf(-mu_v2 / np.maximum(sd_v2, 1e-9))
        p_feas = np.minimum(p1, p2)
        # 可行概率地板：保证在全部不可行时仍有探索方向
        acq = ei * (p_feas + 0.02)

        k = int(np.argmax(acq))
        theta = float(grid[k])
        rec = observe(theta)
        bf = best_feasible()
        rec.update(
            {
                "iter": len(trace),
                "stage": "bo",
                "ei": float(ei[k]),
                "p_feasible": float(p_feas[k]),
                "acq": float(acq[k]),
                "best_theta": bf["theta"] if bf else None,
                "best_objective": bf["objective"] if bf else None,
            }
        )
        trace.append(rec)

        # 收敛判据：连续若干轮可行最优没有改进
        if bf and step > 8:
            recent = [t for t in trace[-9:] if t.get("stage") == "bo"]
            if len(recent) >= 6 and all(
                t.get("best_objective") == bf["objective"] for t in recent
            ):
                break

    bf = best_feasible()
    n_eval = len(xs)
    if bf is None:
        # 约束不可行：**不自行放宽约束**，转人工裁决路径
        v1 = [f - fnr_max for f in fnrs]
        v2 = [p - fpr_max for p in fprs]
        j = int(np.argmin([max(a, b) for a, b in zip(v1, v2)]))
        return {
            "theta": None,
            "fnr": None,
            "fpr": None,
            "cost": None,
            "feasible": False,
            "escalate": True,
            "iterations": n_eval,
            "trace": trace,
            "message": (
                f"约束不可行：在 θ∈[{lo:.3f},{hi:.3f}] 内没有同时满足 "
                f"FNR≤{fnr_max} 与 FPR≤{fpr_max} 的点。"
                "按设计不自行放宽伦理约束——应自动提升门禁等级并报警，把决策权交回人类。"
            ),
            "fnr_max": fnr_max,
            "fpr_max": fpr_max,
            "relaxed": False,
            "n_evaluations": n_eval,
            "closest_candidate": {
                "theta": xs[j],
                "fnr": fnrs[j],
                "fpr": fprs[j],
                "cost": objs[j],
                "fnr_violation": max(0.0, fnrs[j] - fnr_max),
                "fpr_violation": max(0.0, fprs[j] - fpr_max),
            },
        }

    return {
        "theta": bf["theta"],
        "fnr": bf["fnr"],
        "fpr": bf["fpr"],
        "cost": bf["objective"],
        "feasible": True,
        "escalate": False,
        "iterations": n_eval,
        "trace": trace,
        "message": (
            f"找到可行阈值 θ={bf['theta']:.4f}：FNR={bf['fnr']:.4f} ≤ {fnr_max}，"
            f"FPR={bf['fpr']:.4f} ≤ {fpr_max}，对齐成本 C_ali={bf['objective']:.4f}。"
        ),
        "fnr_max": fnr_max,
        "fpr_max": fpr_max,
        "relaxed": False,
        "n_evaluations": n_eval,
    }


# --------------------------------------------------------------------------
# 从实验原始记录标定
# --------------------------------------------------------------------------


def _flatten_records(records: Sequence[dict]) -> list[dict]:
    """把实验原始记录摊平成"单条修改"级别的记录。

    支持三种输入：
      * 含 "mod_records" 的逐次汇总记录（运行器产出）→ 展开并继承严格度与成本；
      * 含 "ground_truth" 的单条修改记录 → 直接使用；
      * 含 "fnr"/"false_block_rate" 的汇总行 → 作为一组直接使用。
    """
    flat: list[dict] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        mods = rec.get("mod_records")
        if isinstance(mods, list) and mods:
            for m in mods:
                item = dict(m)
                for key in ("strictness", "c_ali", "suite", "source", "strategy"):
                    if key in rec and key not in item:
                        item[key] = rec[key]
                flat.append(item)
            continue
        if "ground_truth" in rec:
            flat.append(dict(rec))
            continue
        if "fnr" in rec and "false_block_rate" in rec:
            flat.append(
                {
                    "strictness": rec.get("strictness", rec.get("strategy", 0.0)),
                    "fnr_direct": float(rec.get("fnr", 0.0)),
                    "fpr_direct": float(rec.get("false_block_rate", 0.0)),
                    "cost_direct": float(rec.get("c_ali", 0.0)),
                    "suite": rec.get("suite", ""),
                    "source": rec.get("source", ""),
                }
            )
    return flat


def calibrate_on_records(
    records: list[dict], fnr_max: float, fpr_max: float
) -> dict[str, Any]:
    """从实验原始记录按严格度分组统计 FNR/FPR，再做带约束标定。

    分组依据是记录里的严格度字段（运行器写入 strategy.strictness）；
    若记录没有该字段，则按策略名映射到固定的严格度位置。
    """
    from .strategies import STRICTNESS_BY_STRATEGY  # 延迟导入避免循环依赖

    flat = _flatten_records(records)
    if not flat:
        return {
            "theta": None, "fnr": None, "fpr": None, "cost": None,
            "feasible": False, "escalate": True, "iterations": 0, "trace": [],
            "message": "没有可用于标定的实验记录（缺少 mod_records 或 ground_truth）。",
            "fnr_max": fnr_max, "fpr_max": fpr_max, "relaxed": False,
            "n_evaluations": 0, "groups": [],
        }

    buckets: dict[float, dict[str, Any]] = {}
    for item in flat:
        raw_strict = item.get("strictness")
        if raw_strict is None:
            raw_strict = STRICTNESS_BY_STRATEGY.get(str(item.get("strategy", "")), 0.5)
        try:
            strict = round(float(raw_strict), 3)
        except (TypeError, ValueError):
            strict = 0.5
        b = buckets.setdefault(
            strict,
            {"strictness": strict, "n": 0, "n_dangerous": 0, "n_legit": 0,
             "passed_dangerous": 0, "blocked_legit": 0, "cost_sum": 0.0,
             "cost_n": 0},
        )
        if "fnr_direct" in item:  # 汇总行（只有 FNR/FPR，没有逐条明细）
            b["n"] += 1
            b["n_direct"] = b.get("n_direct", 0) + 1
            b["fnr_direct"] = b.get("fnr_direct", 0.0) + float(item["fnr_direct"])
            b["fpr_direct"] = b.get("fpr_direct", 0.0) + float(item["fpr_direct"])
            b["cost_sum"] += float(item.get("cost_direct", 0.0))
            b["cost_n"] += 1
            continue
        gt = str(item.get("ground_truth", ""))
        action = str(item.get("action_key", item.get("action", "")))
        blocked = item.get("blocked")
        if blocked is None:
            blocked = action.upper() not in ("PASS", "放行", "")
        b["n"] += 1
        if gt == "dangerous":
            b["n_dangerous"] += 1
            if not blocked:
                b["passed_dangerous"] += 1
        else:
            b["n_legit"] += 1
            if blocked:
                b["blocked_legit"] += 1
        cost = item.get("c_ali")
        if cost is not None:
            b["cost_sum"] += float(cost)
            b["cost_n"] += 1

    groups: list[dict[str, Any]] = []
    for strict in sorted(buckets):
        b = buckets[strict]
        if b.get("n_dangerous"):
            fnr = b["passed_dangerous"] / b["n_dangerous"]
        elif b.get("n_direct"):
            fnr = b["fnr_direct"] / b["n_direct"]
        else:
            fnr = 0.0
        if b.get("n_legit"):
            fpr = b["blocked_legit"] / b["n_legit"]
        elif b.get("n_direct"):
            fpr = b["fpr_direct"] / b["n_direct"]
        else:
            fpr = 0.0
        groups.append(
            {
                "strictness": strict,
                "n": b["n"],
                "n_dangerous": b["n_dangerous"],
                "n_legit": b["n_legit"],
                "fnr": fnr,
                "fpr": fpr,
                "cost": (b["cost_sum"] / b["cost_n"]) if b["cost_n"] else 0.0,
            }
        )

    if len(groups) < 2:
        return {
            "theta": None, "fnr": None, "fpr": None, "cost": None,
            "feasible": False, "escalate": True, "iterations": 0, "trace": [],
            "message": (
                f"严格度分组只有 {len(groups)} 组，无法拟合 FNR/FPR 曲线，"
                "请至少提供两个严格度档位的记录。"
            ),
            "fnr_max": fnr_max, "fpr_max": fpr_max, "relaxed": False,
            "n_evaluations": 0, "groups": groups,
        }

    thetas = [g["strictness"] for g in groups]
    problem = EmpiricalCalibrationProblem(
        kind="empirical",
        seed=0,
        drift=0.0,
        theta_min=min(thetas),
        theta_max=max(thetas),
        groups=groups,
    )
    result = calibrate(problem, fnr_max, fpr_max, iterations=40, seed=0)
    result["groups"] = groups
    levels = ", ".join(f"{g['strictness']:.2f}" for g in groups)
    result["message"] = (
        result["message"] + f"（按 {len(groups)} 个严格度档位统计：{levels}）"
    )
    return result
