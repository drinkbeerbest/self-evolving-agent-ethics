"""直播会话管理：线程化运行 EvolutionSession，事件持久化并扇出给 SSE 订阅者。

职责
----
* 每场会话一个后台线程；事件同时写入 data/live/<session_id>.jsonl 与
  各订阅者的队列（SSE 端点逐条取走）。
* 会话可中途停止（stop 后循环在下个检查点退出，已产生的判定全部有效）。
* 历史会话可回放：事件文件就是回放源，前端按时序动画重放。

线程模型：ThreadingHTTPServer 已经是多线程，这里只用 threading.Lock
保护事件列表与订阅者列表；队列用 queue.Queue 的无阻塞 put（慢消费者
丢帧不影响主循环）。
"""
from __future__ import annotations

import json
import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .config import REPO_ROOT
from .minievol import EvolutionSession, SessionOptions

LIVE_DIR = REPO_ROOT / "data" / "live"

__all__ = ["LiveSession", "SessionManager", "manager"]


class LiveSession:
    """一场进化直播。emit 负责落盘 + 扇出。"""

    def __init__(self, opts: SessionOptions, session_id: str | None = None):
        self.session_id = session_id or f"live-{time.strftime('%Y%m%d-%H%M%S')}"
        self.opts = opts
        self.events: list[dict[str, Any]] = []
        self.subs: list[queue.Queue[dict[str, Any]]] = []
        self.lock = threading.Lock()
        self.status = "pending"  # pending | running | done | stopped | error
        self.started_at = time.time()
        self.thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._session: EvolutionSession | None = None
        self._file = LIVE_DIR / f"{self.session_id}.jsonl"
        self._file.parent.mkdir(parents=True, exist_ok=True)

    # -- 生命周期 ---------------------------------------------------------
    def start(self) -> None:
        if self.thread is not None:
            return
        self.status = "running"
        self._session = EvolutionSession(
            self.opts, self._emit, rng_seed=int(time.time()) % 100000
        )
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._session is not None:
            self._session.stop_flag = True

    def _run(self) -> None:
        try:
            if self._session is None:
                self._session = EvolutionSession(
                    self.opts, self._emit, rng_seed=int(time.time()) % 100000
                )
            summary = self._session.run()
            self.status = "stopped" if summary.get("stopped") else "done"
        except Exception as exc:  # pragma: no cover
            self._emit({"type": "error", "message": f"会话异常终止：{exc}"})
            self.status = "error"

    # -- 事件 -------------------------------------------------------------
    def _emit(self, event: dict[str, Any]) -> None:
        event = dict(event)
        event.setdefault("ts", time.time())
        event.setdefault("session_id", self.session_id)
        with self.lock:
            self.events.append(event)
            subs = list(self.subs)
        try:
            with self._file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            pass
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass
        if event.get("type") in ("session_end",):
            self._close_subs()

    def _close_subs(self) -> None:
        with self.lock:
            subs, self.subs = list(self.subs), []
        for q in subs:
            try:
                q.put_nowait({"type": "__end__"})
            except Exception:
                pass

    def subscribe(self) -> queue.Queue[dict[str, Any]]:
        """新订阅者：先补发历史事件，再进入实时流。"""
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=2000)
        with self.lock:
            backlog = list(self.events)
            if self.status in ("running", "pending"):
                self.subs.append(q)
            else:
                backlog.append({"type": "__end__"})
        for evt in backlog:
            try:
                q.put_nowait(evt)
            except queue.Full:
                break
        return q

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "session_id": self.session_id,
                "status": self.status,
                "mode": self.opts.mode,
                "generations": self.opts.generations,
                "pressure": self.opts.pressure,
                "started_at": self.started_at,
                "n_events": len(self.events),
            }


class SessionManager:
    """当前会话 + 历史会话索引（整个服务进程一个实例）。"""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.current: LiveSession | None = None
        self.history: list[str] = []

    def create(self, opts: SessionOptions) -> LiveSession:
        with self.lock:
            if self.current is not None and self.current.status == "running":
                self.current.stop()
            session = LiveSession(opts)
            self.current = session
            self.history.insert(0, session.session_id)
            self.history = self.history[:30]
            session.start()
            return session

    def stop_current(self) -> dict[str, Any]:
        with self.lock:
            if self.current is None:
                return {"ok": False, "message": "当前没有进行中的会话"}
            self.current.stop()
            return {"ok": True, "session_id": self.current.session_id}

    def saved_sessions(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not LIVE_DIR.exists():
            return out
        for f in sorted(LIVE_DIR.glob("*.jsonl"), reverse=True):
            try:
                events = _read_events(f)
                head = next((e for e in events if e.get("type") == "session_start"), {})
                out.append(
                    {
                        "session_id": f.stem,
                        "n_events": len(events),
                        "mode": head.get("mode", "?"),
                        "model": head.get("model", ""),
                        "generations": head.get("generations", 0),
                        "size_kb": round(f.stat().st_size / 1024, 1),
                        "mtime": f.stat().st_mtime,
                    }
                )
            except Exception:
                continue
        return out


def aggregate_sessions(limit: int = 30) -> list[dict[str, Any]]:
    """把历史直播会话聚合为跨视图可用的结构化数据。

    供 /api/pulse 消费：成本账本的"直播实录"、矩阵命中覆盖、
    被拦不变量分布都从这一份数据派生——直播产生的每一次真实判定
    自动进入全局统计，四个视图不再各说各话。
    """
    out: list[dict[str, Any]] = []
    if not LIVE_DIR.exists():
        return out
    for f in sorted(LIVE_DIR.glob("*.jsonl"), reverse=True)[:limit]:
        events = _read_events(f)
        if not events:
            continue
        start = next((e for e in events if e.get("type") == "session_start"), {})
        summary = next((e for e in events if e.get("type") == "session_end"), {})
        stats = summary.get("stats") or {}
        scores = summary.get("score_series") or []
        by_invariant: dict[str, int] = {}
        cells: dict[str, int] = {}
        cost = 0.0
        elapsed = 0.0
        for e in events:
            if e.get("type") not in ("blocked", "applied"):
                continue
            v = e.get("verdict") or {}
            abs_ = (v.get("detail") or {}).get("cost_absolute") or {}
            cost += float(abs_.get("comp_cost") or 0)
            elapsed += float(abs_.get("elapsed_s") or 0)
            for r in v.get("results") or []:
                if r.get("status") == "违反":
                    by_invariant[r.get("invariant", "?")] = by_invariant.get(r.get("invariant", "?"), 0) + 1
            cell = ((v.get("detail") or {}).get("path_key")
                    or f"{(v.get('mod') or {}).get('layer', '')}×{(v.get('mod') or {}).get('autonomy', '')}")
            if e.get("type") == "blocked":
                cells[cell] = cells.get(cell, 0) + 1
        out.append({
            "session_id": f.stem,
            "mode": start.get("mode", "?"),
            "model": start.get("model", ""),
            "scenario": (start.get("scenario") or {}).get("name", ""),
            "scenario_key": (start.get("scenario") or {}).get("key", ""),
            "generations": len(scores),
            "score_series": scores,
            "best": max(scores) if scores else 0,
            "passed": stats.get("passed", 0),
            "blocked": stats.get("blocked", 0),
            "api_tokens": stats.get("api_tokens", 0),
            "gate_cost": round(cost, 6),
            "gate_elapsed_s": round(elapsed, 3),
            "by_invariant": by_invariant,
            "blocked_cells": cells,
            "started_at": start.get("ts", 0),
            "task_ids": start.get("task_ids", []),
            "source_file": f.name,
        })
    return out


def _read_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except Exception:
            continue
    return events


manager = SessionManager()
