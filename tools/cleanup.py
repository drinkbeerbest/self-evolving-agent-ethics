# -*- coding: utf-8 -*-
"""演示遗留文件治理：会话保留 + 审计链归档。

用法：
    python tools/cleanup.py                # 清理：会话保留最近 20 场
    python tools/cleanup.py --keep 10      # 自定义保留场数
    python tools/cleanup.py --rotate-audit # 审计链超过阈值时整体归档并开新链

会话文件（data/live/*.jsonl）：每场一个事件流，保留最近 N 场供回放，其余删除。
审计链（data/audit/audit_chain.jsonl）：append-only 设计，超阈值时把**整个文件**
归档到 data/audit/archive/（自含完整可验证链），当前文件从零开新链——
两个文件各自独立校验通过，历史不被篡改。
"""
import argparse
import shutil
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIVE_DIR = ROOT / "data" / "live"
AUDIT = ROOT / "data" / "audit" / "audit_chain.jsonl"
ARCHIVE_DIR = ROOT / "data" / "audit" / "archive"

KEEP_SESSIONS = 20
AUDIT_ROTATE_MB = 20


def prune_sessions(keep: int) -> int:
    if not LIVE_DIR.exists():
        return 0
    files = sorted(LIVE_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    old = files[keep:]
    removed = 0
    for f in old:
        try:
            f.unlink()
            removed += 1
        except OSError:
            pass
    print(f"会话文件: 保留最新 {min(keep, len(files))} 场，清理 {removed} 个旧文件")
    return removed


def rotate_audit() -> bool:
    if not AUDIT.exists() or AUDIT.stat().st_size < AUDIT_ROTATE_MB * 1024 * 1024:
        size_mb = AUDIT.stat().st_size / 1024 / 1024 if AUDIT.exists() else 0
        print(f"审计链 {size_mb:.1f} MB，未达 {AUDIT_ROTATE_MB} MB 归档阈值")
        return False
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    target = ARCHIVE_DIR / f"audit_chain_{ts}.jsonl"
    shutil.move(str(AUDIT), str(target))
    for extra in AUDIT.parent.glob("audit_chain.jsonl.lock"):
        extra.unlink(missing_ok=True)
    print(f"审计链已归档: {target.name}（{target.stat().st_size / 1024 / 1024:.1f} MB）")
    print("当前文件将从零开新链；归档文件自含完整可验证历史链。")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="演示遗留文件治理")
    ap.add_argument("--keep", type=int, default=KEEP_SESSIONS, help="保留最近 N 场会话")
    ap.add_argument("--rotate-audit", action="store_true", help="审计链超阈值时归档开新链")
    args = ap.parse_args()

    removed = prune_sessions(args.keep)
    rotated = rotate_audit() if args.rotate_audit else False
    if not args.rotate_audit:
        size_mb = AUDIT.stat().st_size / 1024 / 1024 if AUDIT.exists() else 0
        print(f"审计链 {size_mb:.1f} MB（--rotate-audit 可归档开新链）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
