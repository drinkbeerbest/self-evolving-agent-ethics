"""一键配置大模型 API（支持任意 OpenAI 兼容服务商）。

用法：双击 配置API.bat，或 `python tools/configure_api.py`
交互流程：选服务商 → 选模型 → 填 API key → 连通性测试 → 写入 configs/api.yaml

写入的 configs/api.yaml 已被 .gitignore 排除，不会进入版本库。
配置完成后，控制台「进化直播」页选择「真实 API」模式即可接入真模型。
"""
from __future__ import annotations

import getpass
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "configs" / "api.yaml"

# 服务商预设：name -> (base_url, [(model, 说明), ...], key_hint)
PRESETS: dict[str, tuple[str, list[tuple[str, str]], str]] = {
    "智谱 GLM": (
        "https://open.bigmodel.cn/api/paas/v4",
        [("glm-4-flash", "免费模型，演示首选"), ("glm-4-plus", "更强"), ("glm-4-air", "均衡")],
        "在 open.bigmodel.cn 控制台获取（格式 xxxxxx.yyyyyy）",
    ),
    "DeepSeek": (
        "https://api.deepseek.com/v1",
        [("deepseek-chat", "V3 系列对话模型"), ("deepseek-reasoner", "推理模型")],
        "在 platform.deepseek.com 创建",
    ),
    "Moonshot Kimi": (
        "https://api.moonshot.cn/v1",
        [("moonshot-v1-8k", "8K 上下文"), ("moonshot-v1-32k", "32K 上下文")],
        "在 platform.moonshot.cn 创建",
    ),
    "阿里通义 Qwen": (
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
        [("qwen-plus", "均衡"), ("qwen-turbo", "便宜快"), ("qwen-max", "最强")],
        "在阿里云百炼控制台创建（需开通 DashScope 兼容模式）",
    ),
    "OpenAI": (
        "https://api.openai.com/v1",
        [("gpt-4o-mini", "便宜"), ("gpt-4o", "强")],
        "在 platform.openai.com 创建（sk-...）",
    ),
    "OpenRouter": (
        "https://openrouter.ai/api/v1",
        [
            ("openai/gpt-4o-mini", "便宜"),
            ("anthropic/claude-3.5-sonnet", "论文同档模型"),
            ("deepseek/deepseek-chat", "便宜"),
            ("google/gemini-flash-1.5", "免费额度"),
        ],
        "在 openrouter.ai/keys 创建（一个 key 可切换多家模型）",
    ),
    "自定义（任意 OpenAI 兼容服务）": (
        "",
        [],
        "填写服务商给你的 key；base_url 需以 /v1 等兼容根路径结尾",
    ),
}


def hr(title: str = "") -> None:
    line = "─" * 62
    print()
    print(line)
    if title:
        print(f"  {title}")
        print(line)


def ask_choice(prompt: str, choices: list[str]) -> int:
    print()
    for i, c in enumerate(choices, 1):
        print(f"  [{i}] {c}")
    while True:
        raw = input(f"{prompt}（输入序号）: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return int(raw) - 1
        print("  ! 请输入有效序号")


def ask_text(prompt: str, default: str = "", secret: bool = False) -> str:
    suffix = f"（回车用默认 {default}）" if default else ""
    while True:
        raw = (getpass.getpass if secret else input)(f"{prompt}{suffix}: ").strip()
        if raw:
            return raw
        if default:
            return default
        print("  ! 不能为空")


def test_chat(base_url: str, api_key: str, model: str) -> tuple[bool, str]:
    """发一条 5 token 的测试消息，验证 key / model / 网络连通。"""
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": "回复：OK"}],
            "max_tokens": 8,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        reply = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return True, f"连通成功（{(time.time() - t0):.1f}s，模型回复：{reply.strip()[:24] or '…'}）"
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "ignore")[:200]
        except Exception:
            pass
        hint = {401: "key 无效", 403: "无权访问", 404: "模型名或路径错误", 429: "限流/欠费"}.get(
            exc.code, f"HTTP {exc.code}"
        )
        return False, f"{hint}：{detail or exc.reason}"
    except Exception as exc:
        return False, f"网络失败：{exc}"


def main() -> int:
    print("=" * 62)
    print("  伦理熔断控制台 · API 一键配置")
    print("  支持任意 OpenAI 兼容服务商；配置写入 configs/api.yaml")
    print("  （该文件已在 .gitignore 中，密钥不会进入版本库）")
    print("=" * 62)

    names = list(PRESETS.keys())
    idx = ask_choice("选择服务商", names)
    name = names[idx]
    base_url, models, key_hint = PRESETS[name]

    if not base_url:
        base_url = ask_text("Base URL（OpenAI 兼容根路径）")
    if models:
        mi = ask_choice("选择模型", [f"{m}  ——  {d}" for m, d in models] + ["手动输入其他模型"])
        model = models[mi][0] if mi < len(models) else ask_text("模型名")
    else:
        model = ask_text("模型名")

    print(f"\n  API key 获取方式：{key_hint}")
    api_key = ask_text("API key", secret=True)

    # 允许修改预填的 base_url
    if base_url:
        custom = input(f"Base URL 直接回车确认 [{base_url}]: ").strip()
        if custom:
            base_url = custom

    hr("连通性测试")
    print(f"  服务商: {name}")
    print(f"  地址:   {base_url}")
    print(f"  模型:   {model}")
    ok, msg = test_chat(base_url, api_key, model)
    print(f"\n  {'✓' if ok else '✗'} {msg}")
    if not ok:
        retry = input("\n  测试未通过。仍然保存配置吗？[y/N]: ").strip().lower()
        if retry != "y":
            print("  已取消，未写入任何文件。")
            return 1

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    content = (
        "# 由 tools/configure_api.py 生成——勿提交到版本库（已 gitignore）\n"
        f"provider: {name.split('（')[0].strip()}\n"
        f"base_url: {base_url}\n"
        f"api_key: {api_key}\n"
        f"model: {model}\n"
        f"tested_at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"test_ok: {'true' if ok else 'false'}\n"
    )
    CONFIG_PATH.write_text(content, encoding="utf-8")
    hr("完成")
    print(f"  ✓ 配置已写入 {CONFIG_PATH.relative_to(ROOT)}")
    print("  现在打开控制台「进化直播」页，选择「真实 API」模式并点「开始进化」。")
    print("  重启服务（启动项目.bat）后配置同样生效。")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n已取消。")
        sys.exit(130)
