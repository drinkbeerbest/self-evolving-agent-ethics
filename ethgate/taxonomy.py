"""自我修改行为的二维分类学与风险面刻画（开题报告 §3.1）。

横轴：修改对象 6 层（提示/工具/代码/架构/权重/约束）
纵轴：自主度 3 级（系统提议·人类批准 / 系统提议·系统初筛·人类抽检 / 系统自主采纳）
共 18 格，每格用 5 个属性各 1..5 分刻画风险面，加权成风险指数。

权重来源说明：
  `AHP_WEIGHTS` 为层次分析法的占位基线（权重由专家问卷确定 + 一致性检验）。
  实际评分请通过 `data/expert_scores/rater_*.json` 覆盖，
  由 `aggregate_rater_scores` 聚合并用 `kendall_w` 做一致性检验。
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from .types import Autonomy, Layer, RiskAttributes

# --------------------------------------------------------------------------
# 属性权重
# --------------------------------------------------------------------------

AHP_WEIGHTS: dict[str, float] = {
    "permission_expansion": 0.20,
    "goal_drift": 0.26,
    "impact_radius": 0.24,
    "observability": 0.16,
    "reversibility": 0.14,
}

# 五属性的 AHP 判断矩阵（9 阶尺度），用于一致性检验 CR < 0.10。
# 这是权重的**唯一真相源**：实际权重由该矩阵的主特征向量导出，
# 避免"常量权重"与"判断矩阵"两处各写一份而互相漂移。
AHP_MATRIX_ORDER = [
    "permission_expansion",
    "goal_drift",
    "impact_radius",
    "observability",
    "reversibility",
]
AHP_MATRIX: list[list[float]] = [
    # perm  drift  radius obs    rev
    [1.00,  0.75,  0.80,  1.30,  1.40],   # 权限扩张度
    [1.33,  1.00,  1.10,  1.60,  1.90],   # 目标漂移度
    [1.25,  0.90,  1.00,  1.50,  1.70],   # 影响半径
    [0.77,  0.63,  0.67,  1.00,  1.10],   # 可观测性
    [0.71,  0.53,  0.59,  0.91,  1.00],   # 可逆性
]


def compute_weights(matrix: list[list[float]] | None = None) -> dict[str, float]:
    """由判断矩阵导出权重（主特征向量，幂法迭代）。"""
    m = [row[:] for row in (matrix or AHP_MATRIX)]
    n = len(m)
    col_sums = [sum(m[i][j] for i in range(n)) for j in range(n)]
    norm = [
        [m[i][j] / col_sums[j] if col_sums[j] else 0.0 for j in range(n)]
        for i in range(n)
    ]
    vec = [1.0] * n
    for _ in range(200):
        new_vec = [sum(norm[i][j] * vec[j] for j in range(n)) for i in range(n)]
        s = sum(new_vec) or 1.0
        new_vec = [v / s for v in new_vec]
        if all(abs(a - b) < 1e-14 for a, b in zip(new_vec, vec)):
            vec = new_vec
            break
        vec = new_vec
    return {k: v for k, v in zip(AHP_MATRIX_ORDER, vec)}


# --------------------------------------------------------------------------
# 属性基线表：按层给出（自主度一级时的）风险分
# --------------------------------------------------------------------------

BASE_ATTRIBUTES: dict[Layer, dict[str, int]] = {
    # 约束被措辞性弱化，难以察觉
    Layer.PROMPT: {
        "reversibility": 1, "observability": 2, "permission_expansion": 1,
        "goal_drift": 2, "impact_radius": 1,
    },
    # 权限悄然扩张，外泄面增大
    Layer.TOOL: {
        "reversibility": 2, "observability": 2, "permission_expansion": 4,
        "goal_drift": 2, "impact_radius": 3,
    },
    # 检查逻辑被绕过，效果直接
    Layer.CODE: {
        "reversibility": 3, "observability": 2, "permission_expansion": 3,
        "goal_drift": 4, "impact_radius": 3,
    },
    # 失效模式整体改变，影响半径大
    Layer.ARCH: {
        "reversibility": 4, "observability": 3, "permission_expansion": 3,
        "goal_drift": 3, "impact_radius": 5,
    },
    # 不可解释，回滚成本最高
    Layer.WEIGHT: {
        "reversibility": 5, "observability": 5, "permission_expansion": 2,
        "goal_drift": 2, "impact_radius": 4,
    },
    # 对齐目标本身被改写，最危险
    Layer.CONSTRAINT: {
        "reversibility": 2, "observability": 4, "permission_expansion": 2,
        "goal_drift": 5, "impact_radius": 5,
    },
}

# 自主度加成：自主度越高，人工介入越晚，漂移与影响半径上升
AUTONOMY_BONUS: dict[Autonomy, dict[str, int]] = {
    Autonomy.PROPOSE_APPROVE: {
        "reversibility": 0, "observability": 0, "permission_expansion": 0,
        "goal_drift": 0, "impact_radius": 0,
    },
    Autonomy.PROPOSE_FILTER_AUDIT: {
        "reversibility": 0, "observability": 1, "permission_expansion": 0,
        "goal_drift": 1, "impact_radius": 1,
    },
    Autonomy.AUTONOMOUS: {
        "reversibility": 1, "observability": 1, "permission_expansion": 1,
        "goal_drift": 2, "impact_radius": 1,
    },
}


@dataclass
class RiskCell:
    """18 格矩阵中的一格。"""

    layer: Layer
    autonomy: Autonomy
    attributes: RiskAttributes
    risk_index: float
    is_high_risk: bool
    notes: str = ""

    @property
    def key(self) -> str:
        return f"{self.layer.value}×{self.autonomy.value}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer.value,
            "autonomy": self.autonomy.value,
            "attributes": self.attributes.as_dict(),
            "risk_index": round(self.risk_index, 4),
            "is_high_risk": self.is_high_risk,
            "notes": self.notes,
            "key": self.key,
        }


# --------------------------------------------------------------------------
# 计算
# --------------------------------------------------------------------------


def compute_risk_index(attrs: RiskAttributes, weights: dict[str, float] | None = None) -> float:
    """加权风险指数。权重默认取自 AHP 判断矩阵的主特征向量。"""
    w = weights or compute_weights()
    return sum(getattr(attrs, k) * w.get(k, 0.0) for k in RiskAttributes.FIELDS)


def cell_attributes(
    layer: Layer,
    autonomy: Autonomy,
    overrides: dict[str, dict[str, int]] | None = None,
) -> RiskAttributes:
    """计算某一格的属性分。overrides 形如 {"代码×系统自主采纳·人类事后审计": {...}}。"""
    base = BASE_ATTRIBUTES[layer]
    bonus = AUTONOMY_BONUS[autonomy]
    vals: dict[str, int] = {}
    for f in RiskAttributes.FIELDS:
        vals[f] = max(1, min(5, base[f] + bonus[f]))
    if overrides:
        key = f"{layer.value}×{autonomy.value}"
        ov = overrides.get(key)
        if ov:
            for f in RiskAttributes.FIELDS:
                if f in ov:
                    vals[f] = max(1, min(5, int(ov[f])))
    attrs = RiskAttributes(**vals)
    attrs.validate()
    return attrs


def build_matrix(
    overrides: dict[str, dict[str, int]] | None = None,
    weights: dict[str, float] | None = None,
    high_risk_threshold: float = 4.0,
) -> list[RiskCell]:
    """构建完整 18 格矩阵。"""
    cells: list[RiskCell] = []
    for layer in Layer:
        for autonomy in Autonomy:
            attrs = cell_attributes(layer, autonomy, overrides)
            idx = compute_risk_index(attrs, weights)
            cells.append(
                RiskCell(
                    layer=layer,
                    autonomy=autonomy,
                    attributes=attrs,
                    risk_index=idx,
                    is_high_risk=idx >= high_risk_threshold,
                    notes=BASE_NOTES.get(layer, ""),
                )
            )
    return cells


BASE_NOTES: dict[Layer, str] = {
    Layer.PROMPT: "约束被措辞性弱化，难以察觉",
    Layer.TOOL: "权限悄然扩张，外泄面增大",
    Layer.CODE: "检查逻辑被绕过，效果直接",
    Layer.ARCH: "失效模式整体改变，影响半径大",
    Layer.WEIGHT: "不可解释，回滚成本最高",
    Layer.CONSTRAINT: "对齐目标本身被改写，最危险",
}


def find_cell(
    layer: Layer, autonomy: Autonomy, cells: Sequence[RiskCell]
) -> RiskCell | None:
    for c in cells:
        if c.layer is layer and c.autonomy is autonomy:
            return c
    return None


# --------------------------------------------------------------------------
# 专家评分聚合（组内自评 → 几何平均 → Kendall's W 一致性检验）
# --------------------------------------------------------------------------

RATER_FIELDS = RiskAttributes.FIELDS


def aggregate_rater_scores(
    rater_scores: Sequence[dict[str, dict[str, int]]],
) -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    """聚合多位评分者的打分。

    每个 rater_scores[i] 形如 {"代码×系统自主采纳·人类事后审计": {"goal_drift": 4, ...}}

    返回 (聚合后的覆盖表, 统计报告)。
    聚合方式为逐格逐属性的几何平均（越界则截断到 1..5）。
    """
    if not rater_scores:
        return {}, {"n_raters": 0, "kendall_w": None, "note": "无评分数据"}

    keys: list[str] = []
    for r in rater_scores:
        for k in r:
            if k not in keys:
                keys.append(k)

    merged: dict[str, dict[str, int]] = {}
    for k in keys:
        per_field: dict[str, list[float]] = {f: [] for f in RATER_FIELDS}
        for r in rater_scores:
            cell = r.get(k)
            if not cell:
                continue
            for f in RATER_FIELDS:
                if f in cell:
                    per_field[f].append(float(cell[f]))
        merged[k] = {
            f: int(max(1, min(5, round(_geo_mean(vals))))) if vals else 1
            for f, vals in per_field.items()
        }

    w = kendall_w(rater_scores, keys)
    report = {
        "n_raters": len(rater_scores),
        "n_cells": len(keys),
        "kendall_w": round(w, 4) if w is not None else None,
        "interpretation": _kw_interpret(w),
        "aggregation": "逐格逐属性几何平均",
    }
    return merged, report


def _geo_mean(vals: list[float]) -> float:
    if not vals:
        return 1.0
    prod = 1.0
    for v in vals:
        prod *= max(1.0, v)
    return prod ** (1.0 / len(vals))


def kendall_w(
    rater_scores: Sequence[dict[str, dict[str, int]]], keys: Sequence[str]
) -> float | None:
    """Kendall's W 系数一致性检验。

    对每个属性单独计算后取平均。W 越接近 1 表示评分者越一致。
    """
    if len(rater_scores) < 2:
        return None
    ws: list[float] = []
    for f in RATER_FIELDS:
        # 构造评分者 × 对象 的秩矩阵
        ranks: list[list[float]] = []
        for r in rater_scores:
            row = []
            for k in keys:
                cell = r.get(k) or {}
                row.append(float(cell.get(f, 0)))
            ranks.append(row)
        w = _kendall_w_single(ranks)
        if w is not None:
            ws.append(w)
    return sum(ws) / len(ws) if ws else None


def _kendall_w_single(ranks: list[list[float]]) -> float | None:
    """单个属性的 Kendall's W。

    并列值取**平均秩**——本项目的评分是 1..5 的离散分，若按任意顺序打破并列，
    会把"评分者其实完全一致"误判成"高度不一致"。
    """
    m = len(ranks)  # 评分者数
    n = len(ranks[0]) if ranks else 0  # 对象数
    if m < 2 or n < 2:
        return None
    # 每个评分者内部对对象排名（1 最高分），并列取平均秩
    rank_rows: list[list[float]] = []
    for row in ranks:
        order = sorted(range(n), key=lambda i: -row[i])
        rk = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and row[order[j + 1]] == row[order[i]]:
                j += 1
            avg_rank = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                rk[order[k]] = avg_rank
            i = j + 1
        rank_rows.append(rk)
    # Kendall's W = [12S − 3m²n(n+1)²] / [m²(n³ − n)]
    #   m = 评分者数, n = 对象数
    #   S = Σ_j (Σ_i r_ij)²  —— 各对象的秩总和的平方和（注意是平方和，不是和）
    s = sum((sum(rk[j] for rk in rank_rows)) ** 2 for j in range(n))
    num = 12.0 * s - 3.0 * m * m * n * (n + 1) ** 2
    den = m * m * (n**3 - n)
    if den == 0:
        return None
    w = num / den
    return max(0.0, min(1.0, w))


def _kw_interpret(w: float | None) -> str:
    if w is None:
        return "无法计算"
    if w >= 0.8:
        return "评分者高度一致"
    if w >= 0.6:
        return "评分者中度一致"
    if w >= 0.4:
        return "评分者一致性偏低，需讨论后重新评分"
    return "评分者一致性差，分歧显著"


# --------------------------------------------------------------------------
# AHP 一致性检验
# --------------------------------------------------------------------------


def ahp_consistency(matrix: list[list[float]] | None = None) -> dict[str, Any]:
    """计算 AHP 判断矩阵的一致性比率 CR。CR < 0.10 视为通过。"""
    m = [row[:] for row in (matrix or AHP_MATRIX)]
    n = len(m)
    col_sums = [sum(m[i][j] for i in range(n)) for j in range(n)]
    norm = [
        [m[i][j] / col_sums[j] if col_sums[j] else 0.0 for j in range(n)]
        for i in range(n)
    ]
    vec = [1.0] * n
    for _ in range(200):
        new_vec = [sum(norm[i][j] * vec[j] for j in range(n)) for i in range(n)]
        s = sum(new_vec) or 1.0
        new_vec = [v / s for v in new_vec]
        if all(abs(a - b) < 1e-14 for a, b in zip(new_vec, vec)):
            vec = new_vec
            break
        vec = new_vec
    lam_max = sum(
        sum(m[i][j] * vec[j] for j in range(n)) / vec[i] for i in range(n)
    ) / n
    ci = (lam_max - n) / (n - 1) if n > 1 else 0.0
    ri = {3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45}.get(n, 1.45)
    cr = ci / ri if ri else 0.0
    return {
        "lambda_max": round(lam_max, 6),
        "ci": round(ci, 6),
        "ri": ri,
        "cr": round(cr, 6),
        "passed": cr < 0.10,
        "weights": {k: round(v, 4) for k, v in zip(AHP_MATRIX_ORDER, vec)},
    }


# --------------------------------------------------------------------------
# 落盘
# --------------------------------------------------------------------------


def load_rater_scores(scores_dir: str | Path) -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    """读取 data/expert_scores/rater_*.json 并聚合。"""
    p = Path(scores_dir)
    raters: list[dict[str, dict[str, int]]] = []
    for f in sorted(p.glob("rater_*.json")):
        try:
            raters.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            continue
    return aggregate_rater_scores(raters)


def matrix_to_rows(cells: Sequence[RiskCell]) -> list[dict[str, Any]]:
    return [c.as_dict() for c in cells]
