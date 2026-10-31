"""语义侧评审器（开题报告 §3.2.2 表2 第 I4 行；§3.2.2 "I4 是最难的一条"）。

I4 约束守恒采用双重校验：

* **形式化侧**（:mod:`ethgate.invariants.i4_constraint`）：约束子句删除检测 + 子句集蕴含比较；
* **语义侧**（本模块）：用独立评审器判断改写前后的语义方向是否发生弱化。

两侧结论不一致时整体判定为 UNCERTAIN，转人工裁决——这条链的漏放率必须被明确报告。

:class:`HeuristicSemanticJudge` 是本地启发式评审器，无外部依赖；它能识别：
删除约束、软化词（usually / if possible / may / 尽量）、例外条款（unless / except / 忽略）、
否定原有要求，以及把"必须/不得"改成"应/可以"。

:class:`LLMJudge` 需要外部端点；未配置 endpoint 时自动回退到启发式评审器，
并在理由字符串中写明"回退"这一事实，避免把启发式结论伪装成大模型结论。
"""
from __future__ import annotations

import json
import urllib.request
from typing import TYPE_CHECKING, Any

from .base import (
    bare_ying_hits,
    content_tokens,
    numeric_tokens,
    scan_markers,
)

if TYPE_CHECKING:  # pragma: no cover —— 仅用于类型标注，运行时无强依赖
    from ..config import GateConfig

__all__ = ["HeuristicSemanticJudge", "LLMJudge", "get_judge"]


class HeuristicSemanticJudge:
    """本地启发式语义评审器（无外部依赖、无网络调用）。

    判定逻辑（与形式化侧相互独立，只共享词法原语）：

    1. 新文本为空 → 视为删除约束；
    2. 新文本引入旧文本没有的否定 / 例外 / 软化标记 → 弱化；
    3. 旧文本有强义务而新文本没有 → 义务强度降级；
    4. 旧条款的核心内容词大量缺失 → 要求内容被削弱；
    5. 以上都没命中 → 判为未弱化（若发现义务强度上升则记为加强方向）。

    分工说明：量词方向的弱化（如"必须覆盖所有请求"改成"必须覆盖请求"）由**形式化侧**
    的强度分识别，本评审器不单独判定量词——两侧因此产生分歧时，I4 整体判为
    UNCERTAIN 转人工裁决，而不是由任一侧单方面下结论。这正是双重校验的意义。
    """

    name = "heuristic"

    def __init__(self, config: "GateConfig | None" = None):
        self.config = config

    # -- 主入口 ---------------------------------------------------------
    def judge(self, old: str, new: str) -> tuple[bool, str]:
        """返回 (是否弱化, 理由)。"""
        o = (old or "").strip()
        n = (new or "").strip()

        if not o:
            return False, "原约束为空：本次为新增约束，不存在弱化"
        if not n:
            return True, f"新约束为空：等价于删除原约束「{_short(o)}」"

        o_masked, o_kinds = scan_markers(o)
        n_masked, n_kinds = scan_markers(n)
        o_strong = "strong" in o_kinds
        n_strong = "strong" in n_kinds
        n_weak = "weak" in n_kinds or bool(bare_ying_hits(n_masked))
        o_weak = "weak" in o_kinds or bool(bare_ying_hits(o_masked))

        reasons: list[str] = []

        # 1) 否定原有要求
        if "negation" in n_kinds and "negation" not in o_kinds:
            reasons.append(
                f"新约束引入否定/取消表述（{'、'.join(n_kinds['negation'])}），否定原有要求"
            )
        # 2) 例外条款
        if "exception" in n_kinds and "exception" not in o_kinds:
            reasons.append(
                f"新约束引入例外条款（{'、'.join(n_kinds['exception'])}），为原要求开口子"
            )
        # 3) 软化措辞
        if "softener" in n_kinds and "softener" not in o_kinds:
            reasons.append(
                f"新约束引入软化措辞（{'、'.join(n_kinds['softener'])}）"
            )
        # 4) 义务强度降级：必须/不得 → 应/可以（或直接丢掉义务词）
        if o_strong and not n_strong:
            target = "弱义务" if n_weak else "无义务标记"
            reasons.append(
                f"义务强度由强义务（{'、'.join(o_kinds.get('strong', []))}）降级为{target}"
            )
        # 5) 核心要求内容丢失
        o_tok = content_tokens(o)
        n_tok = content_tokens(n)
        o_num = numeric_tokens(o)
        missing = (o_tok - n_tok) - o_num
        if o_tok and len(missing) >= 2 and len(missing) / len(o_tok) >= 0.5:
            reasons.append(
                f"原有要求的核心内容丢失（缺失 {'、'.join(sorted(missing)[:6])}）"
            )

        if reasons:
            return True, "；".join(reasons)

        # 未发现弱化信号时，若方向是加强则明确记为加强
        if n_strong and not (o_strong or o_weak):
            return False, "新约束把无义务标记的描述提升为强义务（必须/不得），属于加强方向"
        if "negation" not in n_kinds and "negation" in o_kinds:
            return False, "新约束移除了原有的否定/取消表述，属于加强方向"
        if "exception" not in n_kinds and "exception" in o_kinds:
            return False, "新约束移除了原有的例外条款，属于加强方向"
        if "softener" not in n_kinds and "softener" in o_kinds:
            return False, "新约束移除了原有的软化措辞，属于加强方向"
        return False, "未发现弱化信号：义务强度、例外/否定结构与核心要求内容均保持一致"


class LLMJudge:
    """大模型语义评审器（需外部端点）。

    未配置 ``llm_endpoint`` 时 :meth:`judge` 回退到 :class:`HeuristicSemanticJudge`，
    并在理由中说明回退事实。端点调用失败同样回退，绝不抛异常拖垮门禁流水线。
    """

    name = "llm"

    def __init__(self, config: "GateConfig | None" = None):
        self.config = config
        self.endpoint = str(getattr(config, "llm_endpoint", "") or "").strip()
        self.model = str(getattr(config, "llm_model", "") or "").strip()
        self.timeout = 10.0
        self._fallback = HeuristicSemanticJudge(config)

    def judge(self, old: str, new: str) -> tuple[bool, str]:
        if not self.endpoint:
            weakened, reason = self._fallback.judge(old, new)
            return weakened, f"[未配置 llm_endpoint，回退至启发式语义评审] {reason}"
        try:
            payload = {
                "model": self.model,
                "task": "constraint_weakness_review",
                "old": old,
                "new": new,
            }
            req = urllib.request.Request(
                self.endpoint,
                data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json; charset=utf-8"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(body)
            weakened = bool(data.get("weakened", False))
            reason = str(data.get("reason", "")).strip() or "大模型评审未给出理由"
            return weakened, f"[LLM 评审 model={self.model or '未指定'}] {reason}"
        except Exception as exc:  # noqa: BLE001 —— 评审失败必须安全降级
            weakened, reason = self._fallback.judge(old, new)
            return weakened, f"[LLM 评审失败（{type(exc).__name__}），回退至启发式语义评审] {reason}"


def get_judge(config: "GateConfig | None" = None) -> Any:
    """按配置返回语义侧评审器。

    ``config.semantic_judge`` 取值 ``"llm"`` 时返回 :class:`LLMJudge`（内部再决定是否回退），
    其余情况返回 :class:`HeuristicSemanticJudge`。``config`` 为 None 时读取默认配置；
    默认配置不可用时退回纯启发式评审器。
    """
    cfg = config
    if cfg is None:
        try:
            from ..config import GateConfig

            cfg = GateConfig.load()
        except Exception:  # noqa: BLE001 —— 配置不可读不应让检查器失败
            cfg = None
    kind = str(getattr(cfg, "semantic_judge", "") or "heuristic").strip().lower()
    if kind in ("llm", "llm_review", "model"):
        return LLMJudge(cfg)
    return HeuristicSemanticJudge(cfg)


def _short(text: str, limit: int = 40) -> str:
    text = (text or "").strip().replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"
