"""四条伦理不变量的公共基座（开题报告 §3.2.2 表2）。

提供两类公共设施：

1. **异常护栏** :func:`guarded`
   检查器内部任何异常都降级为 ``CheckStatus.UNCERTAIN``，绝不让门禁流水线崩掉。
   硬性要求：不确定时返回 UNCERTAIN，既不抛异常，也不误判 FAIL。

2. **文本分析原语**
   义务强度（必须/不得 → 应/可以）、软化词、例外条款、否定表述四类标记的识别，
   以及约束子句"内容词"抽取。形式化侧（:mod:`ethgate.invariants.i4_constraint`）与
   语义侧（:mod:`ethgate.invariants.semantic`）共用这一层词法原语，但判定流程
   相互独立：形式化侧做子句集蕴含比较，语义侧做弱化方向判断。两侧结论不一致
   即为 I4 的人工裁决信号。

这些原语都是启发式的：它们只能覆盖可枚举的语言现象，因此凡是基于它们的判定，
误差界里都必须写明残余漏放来源，不得写成零。
"""
from __future__ import annotations

import functools
import hashlib
import math
import re
from typing import Any, Callable, Iterable

from ..types import CheckResult, CheckStatus, Modification, SystemState

__all__ = [
    "guarded",
    "clopper_pearson_upper",
    "sample_size_for_bound",
    "normalize_text",
    "content_tokens",
    "scan_markers",
    "marker_kinds",
    "obligation_level",
    "strength_score",
    "MARKER_KINDS",
    "UNIVERSAL_QUANTIFIERS",
    "EXISTENTIAL_QUANTIFIERS",
]


# --------------------------------------------------------------------------
# 异常护栏
# --------------------------------------------------------------------------


def guarded(invariant: str, method: str) -> Callable[[Callable[..., CheckResult]], Callable[..., CheckResult]]:
    """把检查器包成"永不抛异常"的版本。

    任何内部异常都转成 ``CheckStatus.UNCERTAIN``，并把异常类型写进证据，
    使门禁流水线能安全地把这类提案升级到沙箱或人工裁决，而不是整体崩掉。
    """

    def deco(fn: Callable[..., CheckResult]) -> Callable[..., CheckResult]:
        @functools.wraps(fn)
        def wrapper(mod: Modification, state: SystemState) -> CheckResult:
            try:
                res = fn(mod, state)
            except Exception as exc:  # noqa: BLE001 —— 护栏本身必须兜住一切
                return CheckResult(
                    invariant=invariant,
                    status=CheckStatus.UNCERTAIN,
                    summary=f"{invariant} 检查器内部异常，无法完成判定，转人工复核：{type(exc).__name__}: {exc}",
                    evidence=[f"异常类型 {type(exc).__name__}", f"异常信息：{exc}"],
                    method=method,
                    error_bound="检查未完成，无误差界可估计；按保守原则记为不确定，不得据此判定通过",
                    detail={"exception": type(exc).__name__, "message": str(exc)},
                )
            return _normalize(res, invariant, method)

        return wrapper

    return deco


def _normalize(res: Any, invariant: str, method: str) -> CheckResult:
    """结果规整：保证字段齐全、证据非空、状态合法。"""
    if not isinstance(res, CheckResult):
        return CheckResult(
            invariant=invariant,
            status=CheckStatus.UNCERTAIN,
            summary=f"{invariant} 检查器返回了非法结果类型 {type(res).__name__}",
            evidence=[f"非法返回类型：{type(res).__name__}"],
            method=method,
            error_bound="检查未完成，无误差界可估计",
            detail={},
        )
    res.invariant = res.invariant or invariant
    res.method = res.method or method
    res.summary = res.summary or f"{invariant} 判定摘要缺失"
    if not isinstance(res.status, CheckStatus):
        try:
            res.status = CheckStatus(res.status)
        except Exception:
            res.status = CheckStatus.UNCERTAIN
    if not res.evidence:
        # 证据为空说明检查没有真正跑完，不能当成通过
        res.status = CheckStatus.UNCERTAIN
        res.evidence = [f"{invariant} 未产出任何具体证据，按保守原则记为不确定"]
    if not res.error_bound:
        res.error_bound = "误差界说明缺失（检查器实现缺陷），暂按不确定处理"
    return res


# --------------------------------------------------------------------------
# 统计：抽样误差界
# --------------------------------------------------------------------------


def clopper_pearson_upper(failures: int, n: int, alpha: float = 0.05) -> float:
    """失败率的 Clopper-Pearson 精确上界（单侧置信度 1-alpha）。

    解方程 ``P(X <= failures | n, p) = alpha`` 得到 p 的上界。
    抽样量很小时这个上界会非常宽——这正是需要诚实写进 error_bound 的东西。
    """
    if n <= 0 or failures >= n:
        return 1.0
    if failures < 0:
        failures = 0

    def cdf(p: float) -> float:
        total = 0.0
        for k in range(failures + 1):
            total += math.comb(n, k) * (p ** k) * ((1.0 - p) ** (n - k))
        return total

    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if cdf(mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi


def sample_size_for_bound(eps: float, alpha: float = 0.05) -> int:
    """要给出"失败率 <= eps"的可证上界（零失败时）所需的最小抽样量。"""
    if eps <= 0 or eps >= 1:
        return 0
    return int(math.ceil(math.log(alpha) / math.log(1.0 - eps)))


# --------------------------------------------------------------------------
# 词法原语
# --------------------------------------------------------------------------

# 标记词 → 语义类别。ASCII 词统一小写登记；中文无大小写。
MARKER_KINDS: dict[str, tuple[str, ...]] = {
    # 强义务：必须 / 不得 / 禁止
    "必须": ("strong",),
    "务必": ("strong",),
    "一律": ("strong",),
    "只能": ("strong",),
    "不得": ("strong",),
    "禁止": ("strong",),
    "严禁": ("strong",),
    "不能": ("strong",),
    "must": ("strong",),
    "shall": ("strong",),
    "never": ("strong",),
    "cannot": ("strong",),
    "always": ("strong",),
    # 弱义务：应 / 可以 / 建议
    "应当": ("weak",),
    "应予": ("weak",),
    "可以": ("weak",),
    "建议": ("weak",),
    "允许": ("weak",),
    "宜": ("weak",),
    "should": ("weak",),
    "may": ("weak", "softener"),
    "can": ("weak",),
    "could": ("weak",),
    # 软化词：usually / if possible / 尽量
    "通常": ("softener",),
    "一般来说": ("softener",),
    "一般": ("softener",),
    "大体": ("softener",),
    "原则上": ("softener",),
    "尽可能": ("softener",),
    "尽量": ("softener",),
    "酌情": ("softener",),
    "视情况": ("softener",),
    "usually": ("softener",),
    "generally": ("softener",),
    "typically": ("softener",),
    "often": ("softener",),
    "if possible": ("softener",),
    "when possible": ("softener",),
    "where possible": ("softener",),
    "in most cases": ("softener",),
    "as much as possible": ("softener",),
    "preferably": ("softener",),
    # 例外条款：unless / except / 忽略
    "除非": ("exception",),
    "除外": ("exception",),
    "例外": ("exception",),
    "忽略": ("exception",),
    "不包括": ("exception",),
    "不适用": ("exception",),
    "apart from": ("exception",),
    "unless": ("exception",),
    "except": ("exception",),
    "excluding": ("exception",),
    "ignore": ("exception",),
    # 否定原有要求：不再 / 无需 / 不必
    "不再": ("negation",),
    "不需要": ("negation",),
    "无需": ("negation",),
    "不必": ("negation",),
    "不用": ("negation",),
    "取消": ("negation",),
    "废除": ("negation",),
    "豁免": ("negation",),
    "免除": ("negation",),
    "no longer": ("negation",),
    "not required": ("negation",),
    "don't need": ("negation",),
    "do not need": ("negation",),
}

# 量词：全称强于存在
UNIVERSAL_QUANTIFIERS: tuple[str, ...] = (
    "所有", "全部", "每个", "各个", "每次", "一律", "任何", "every", "all",
)
EXISTENTIAL_QUANTIFIERS: tuple[str, ...] = (
    "部分", "某些", "大多数", "部分情况", "some", "most",
)

# 子句起始位置（用于裸"应"的边界判定，避免误伤"响应/应用"）
_CLAUSE_BOUNDARY = set("，,。；;：:、\n\r\t 　（）()【】[]{}《》\"'“”‘’!！?？")

# 停用词：函数词不参与"核心要求内容"的比较
_STOPWORDS = {
    "的", "了", "和", "与", "及", "或", "在", "是", "对", "把", "被", "等",
    "时", "中", "个", "上", "下", "该", "本", "其", "此", "将", "则", "都",
    "还", "很", "更", "再", "又", "只", "从", "到", "让", "使", "由", "为",
    "以", "并", "但", "而", "且", "所", "之", "有", "也", "我", "你", "他",
    "它", "这", "那", "些", "如", "若", "不", "没", "着", "过",
    "the", "a", "an", "of", "to", "and", "or", "in", "on", "for", "with",
    "be", "is", "are", "was", "were", "that", "this", "it", "as", "by",
    "at", "from", "we", "they",
}

_PUNCT_RE = re.compile(
    r"[\s，。；;：:、,.\"'“”‘’()（）\[\]【】{}<>《》!！?？\-—_/\\|~`@#$%^&*+=]+"
)
_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*|\d+|[一-鿿]")


def _marker_pattern() -> re.Pattern[str]:
    """构造一次性匹配所有标记词的正则（按长度降序，保证长词优先）。"""
    parts: list[str] = []
    for mk in sorted(MARKER_KINDS, key=len, reverse=True):
        if mk.isascii():
            # ASCII 词用"非 ASCII 字母数字"边界，避免与汉字相连时失效
            parts.append(r"(?:(?<![A-Za-z0-9_])" + re.escape(mk) + r"(?![A-Za-z0-9_]))")
        else:
            parts.append(re.escape(mk))
    return re.compile("|".join(parts), re.IGNORECASE)


_MARKER_RE = _marker_pattern()


def scan_markers(text: str) -> tuple[str, dict[str, list[str]]]:
    """扫描并遮蔽标记词。

    返回 ``(遮蔽后的文本, {类别: [命中词]})``。遮蔽用等长空格替换，
    因此字符位置保持不变，便于后续做边界判定。
    """
    kinds: dict[str, list[str]] = {}

    def repl(m: re.Match[str]) -> str:
        hit = m.group(0)
        for kind in MARKER_KINDS.get(hit.lower(), ()):
            kinds.setdefault(kind, []).append(hit)
        return " " * len(hit)

    masked = _MARKER_RE.sub(repl, text or "")
    return masked, kinds


def marker_kinds(text: str) -> dict[str, list[str]]:
    """只取标记命中类别。"""
    return scan_markers(text)[1]


def bare_ying_hits(masked: str) -> list[str]:
    """裸"应"只有在子句起始位置才算义务词，避免把"响应/应用/效应"误判为弱义务。"""
    hits: list[str] = []
    for i, ch in enumerate(masked):
        if ch != "应":
            continue
        if i == 0 or masked[i - 1] in _CLAUSE_BOUNDARY:
            hits.append("应")
    return hits


def obligation_level(text: str) -> int:
    """义务强度等级：3=强义务，2=弱义务，1=仅软化措辞，0=无义务标记。"""
    masked, kinds = scan_markers(text)
    if "strong" in kinds:
        return 3
    if "weak" in kinds or bare_ying_hits(masked):
        return 2
    if "softener" in kinds:
        return 1
    return 0


def _has_quantifier(text: str, table: Iterable[str]) -> bool:
    low = (text or "").lower()
    for q in table:
        if q.isascii():
            if re.search(r"(?<![A-Za-z0-9_])" + re.escape(q) + r"(?![A-Za-z0-9_])", low):
                return True
        elif q in text:
            return True
    return False


def strength_score(text: str) -> int:
    """形式化侧的条款强度分（用于子句集蕴含比较）。

    分值越高越强。量词方向、例外条款、否定表述都参与计分。
    """
    masked, kinds = scan_markers(text)
    score = obligation_level(text)
    if _has_quantifier(text, UNIVERSAL_QUANTIFIERS):
        score += 1
    if _has_quantifier(text, EXISTENTIAL_QUANTIFIERS):
        score -= 1
    if "exception" in kinds:
        score -= 1
    if "negation" in kinds:
        score -= 1
    if bare_ying_hits(masked):
        score += 0  # 裸"应"已计入 obligation_level
    return score


def normalize_text(s: str) -> str:
    """归一化文本（去空白与标点、转小写），用于子句等价比较。"""
    return _PUNCT_RE.sub("", (s or "").lower())


def content_tokens(text: str) -> set[str]:
    """抽取条款的"核心内容词"（去掉义务/软化/例外/否定标记与停用词）。

    中文按单字切、英文按词、数字单列。数字在语义比较中单独处理，
    避免"3 秒 → 1 秒"这类纯数值变化被误判成内容丢失。
    """
    masked, _ = scan_markers(text)
    tokens: set[str] = set()
    for m in _TOKEN_RE.finditer(masked):
        tok = m.group(0).lower()
        if tok in _STOPWORDS:
            continue
        tokens.add(tok)
    return tokens


def numeric_tokens(text: str) -> set[str]:
    """抽取条款中的数字（单独用于"数值是否被削弱"的判定）。"""
    masked, _ = scan_markers(text)
    return {m.group(0) for m in re.finditer(r"\d+", masked)}


def stable_seed(*parts: Any) -> int:
    """由提案标识派生确定性随机种子，保证抽样可复现。"""
    blob = "|".join(str(p) for p in parts)
    return int(hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12], 16)
