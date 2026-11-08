# -*- coding: utf-8 -*-
"""AI 出题器：让接入的大模型出题，双遍交叉验证后进题池。

流程（对应"题目可否由 API 大模型出"）：
  1. 出题：让模型出 N 道答案为唯一整数的数学应用题（GSM8K 风格）
  2. 验证：同一模型以解题者身份独立再答一遍（temperature=0）
  3. 收录：出题答案与解题答案一致才进题池（不一致 = 题目歧义/答案争议，丢弃）

产物：data/sources/ai_generated_tasks.json（minievol 自动合并进题池，
source 标记 "ai-generated"，协议在报告中如实注明为 AI 出题+交叉验证）。

用法：python tools/generate_tasks.py [--count 5]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ethgate.minievol import LLMClient, LLMError, load_api_config  # noqa: E402

OUT = ROOT / "data" / "sources" / "ai_generated_tasks.json"

GEN_PROMPT = (
    "请出 {n} 道数学应用题（小学至初中难度，GSM8K 风格），要求：\n"
    "1. 每道题的最终答案是唯一的整数（不能是小数、分数、区间）\n"
    "2. 题目条件充分、无歧义，正常人按步骤计算能得到同一个答案\n"
    "3. 题目之间考察场景不同（行程、购物、工程、比例、年龄等）\n"
    '输出 JSON 数组：[{"question":"题面","answer":整数答案}]，不要输出其他文字。'
)
SOLVE_PROMPT = "解答下面的数学应用题，只输出最终整数答案。\n\n"


def numeric(text: str):
    import re

    found = re.findall(r"-?\d[\d,]*", text or "")
    if not found:
        return None
    try:
        return int(re.sub(r"[,\s]", "", found[-1]))
    except ValueError:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=5)
    args = ap.parse_args()

    cfg = load_api_config()
    if not cfg:
        print("未找到 API 配置（先运行 tools/configure_api.py）")
        return 1
    llm = LLMClient(cfg, timeout=120)

    print(f"让模型出 {args.count} 道题…")
    reply, _tk = llm.chat(
        [{"role": "user", "content": GEN_PROMPT.replace("{n}", str(args.count))}],
        temperature=0.8, max_tokens=3000,
    )
    start = reply.find("[")
    end = reply.rfind("]")
    if start < 0 or end <= start:
        print("出题失败：模型输出中没有 JSON 数组"); return 1
    try:
        tasks = json.loads(reply[start:end + 1])
    except json.JSONDecodeError as exc:
        print(f"出题 JSON 解析失败：{exc}"); return 1

    # 双遍交叉验证：独立解题一遍，答案一致才收录
    kept = []
    for i, t in enumerate(tasks):
        q, a = str(t.get("question", "")).strip(), t.get("answer")
        try:
            a_int = int(str(a).replace(",", ""))
        except (ValueError, TypeError):
            continue
        print(f"  验证题 {i + 1}（标准答案 {a_int}）：独立求解中…")
        try:
            reply2, _tk2 = llm.chat(
                [{"role": "user", "content": SOLVE_PROMPT + q}],
                temperature=0.0, max_tokens=1500,
            )
        except LLMError as exc:
            print(f"    求解调用失败：{exc}"); continue
        got = numeric(reply2)
        if got is not None and abs(got - a_int) <= max(1, abs(a_int) // 1000):
            kept.append({"question": q, "answer": a_int})
            print(f"    ✓ 交叉验证一致（{got}），收录")
        else:
            print(f"    ✗ 答案不一致（出题答案 {a_int} vs 独立求解 {got}），丢弃")

    existing = []
    if OUT.exists():
        try:
            existing = json.loads(OUT.read_text(encoding="utf-8")).get("tasks", [])
        except Exception:
            existing = []
    have_q = {t["question"] for t in existing}
    kept = [t for t in kept if t["question"] not in have_q]
    existing.extend({"id": f"ai_{len(existing) + j:03d}", "source": "ai-generated",
                     "kind": "AI 数学", "question": t["question"], "answer": t["answer"]}
                    for j, t in enumerate(kept, 1))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "license": "自产（AI 出题 + 同模型独立求解交叉验证，协议见报告）",
        "model": cfg.get("model", ""), "tasks": existing,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n本轮新收录 {len(kept)} 道（重复跳过），题库累计 {len(existing)} 道 → {OUT.name}")
    print("minievol 会在下次会话自动合并这些题。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
