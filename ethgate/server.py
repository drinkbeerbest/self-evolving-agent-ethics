"""HTTP 服务：对外暴露原型系统的 API，同时托管 web/ 前端静态页。

只用标准库 http.server，无 Web 框架依赖。启动：
    python -m ethgate.cli serve --port 8000
或
    python -m ethgate.server --port 8000
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from .audit import AuditChain
from .config import GateConfig, REPO_ROOT
from .taxonomy import ahp_consistency, build_matrix, load_rater_scores, matrix_to_rows
from .types import (
    AdmissionAction,
    Autonomy,
    CheckStatus,
    FileChange,
    GateLevel,
    Layer,
    Modification,
    SystemState,
    to_jsonable,
)

WEB_DIR = REPO_ROOT / "web"
DATA_DIR = REPO_ROOT / "data"


# --------------------------------------------------------------------------
# 反序列化辅助
# --------------------------------------------------------------------------


def file_change_from_dict(d: dict[str, Any]) -> FileChange:
    return FileChange(
        path=d.get("path", ""),
        added=list(d.get("added", [])),
        removed=list(d.get("removed", [])),
        is_test=bool(d.get("is_test", False)),
        is_constraint=bool(d.get("is_constraint", False)),
        is_evaluation=bool(d.get("is_evaluation", False)),
        is_shutdown=bool(d.get("is_shutdown", False)),
    )


def modification_from_dict(d: dict[str, Any]) -> Modification:
    """从 JSON 字典还原 Modification（前端提交 / 数据集加载共用）。"""
    layer = Layer(d["layer"]) if d.get("layer") else Layer.CODE
    autonomy = Autonomy(d["autonomy"]) if d.get("autonomy") else Autonomy.AUTONOMOUS
    rewrites = [tuple(r) for r in d.get("constraint_rewrites", [])]
    return Modification(
        mod_id=d.get("mod_id", ""),
        agent_id=d.get("agent_id", "agent"),
        round_index=int(d.get("round_index", 0)),
        layer=layer,
        autonomy=autonomy,
        title=d.get("title", ""),
        rationale=d.get("rationale", ""),
        files=[file_change_from_dict(f) for f in d.get("files", [])],
        new_tools=list(d.get("new_tools", [])),
        new_syscalls=list(d.get("new_syscalls", [])),
        new_network_hosts=list(d.get("new_network_hosts", [])),
        removed_constraints=list(d.get("removed_constraints", [])),
        added_constraints=list(d.get("added_constraints", [])),
        constraint_rewrites=rewrites,
        log_level_delta=int(d.get("log_level_delta", 0)),
        hardcode_detected=bool(d.get("hardcode_detected", False)),
        weakens_test_coverage=bool(d.get("weakens_test_coverage", False)),
        changes_evaluation_logic=bool(d.get("changes_evaluation_logic", False)),
        added_prompts=list(d.get("added_prompts", [])),
        removed_prompts=list(d.get("removed_prompts", [])),
        proposed_architecture=list(d.get("proposed_architecture", [])),
        affected_modules=list(d.get("affected_modules", [])),
        base_commit=d.get("base_commit", ""),
        created_at=float(d.get("created_at") or time.time()),
        source=d.get("source", "manual"),
    )


def state_from_dict(d: dict[str, Any]) -> SystemState:
    return SystemState(
        prompt_set=list(d.get("prompt_set", [])),
        tool_table=list(d.get("tool_table", [])),
        syscalls_allowed=list(d.get("syscalls_allowed", [])),
        constraints=list(d.get("constraints", [])),
        modules={k: list(v) for k, v in (d.get("modules") or {}).items()},
        shutdown_module=d.get("shutdown_module", ""),
        architecture=list(d.get("architecture", [])),
        code_version=d.get("code_version", "v0"),
    )


# --------------------------------------------------------------------------
# 数据读取
# --------------------------------------------------------------------------


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def _results_dir() -> Path:
    return DATA_DIR / "results"


def load_summaries() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    d = _results_dir()
    if not d.exists():
        return out
    for f in sorted(d.glob("summary_*.json")):
        data = _read_json(f)
        if isinstance(data, list):
            out.extend(data)
        elif isinstance(data, dict):
            rows = data.get("rows") or data.get("summary") or []
            out.extend(rows)
    return out


def load_raw(suite: str | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    d = _results_dir()
    if not d.exists():
        return out
    files = sorted(d.glob("raw_*.json")) if not suite else [d / f"raw_{suite}.json"]
    for f in files:
        data = _read_json(f)
        if isinstance(data, list):
            out.extend(data)
        elif isinstance(data, dict):
            out.extend(data.get("rows") or data.get("raw") or [])
    return out


def load_dataset_file(name: str) -> list[dict[str, Any]]:
    p = DATA_DIR / "datasets" / f"{name}.json"
    data = _read_json(p, [])
    if isinstance(data, dict):
        return data.get("mods") or data.get("rows") or []
    return data or []


def dataset_index() -> list[dict[str, Any]]:
    d = DATA_DIR / "datasets"
    out: list[dict[str, Any]] = []
    if not d.exists():
        return out
    # 兼容无扩展名的历史文件（早期 CLI 未补 .json 后缀）
    files = sorted(set(d.glob("*.json")) | {p for p in d.iterdir()
                                          if p.is_file() and p.suffix == ""})
    for f in files:
        rows = load_dataset_file(f.stem)
        if not rows:
            continue
        by_source: dict[str, int] = {}
        by_layer: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for r in rows:
            s = r.get("source", "?")
            by_source[s] = by_source.get(s, 0) + 1
            ly = r.get("layer", "?")
            by_layer[ly] = by_layer.get(ly, 0) + 1
            for h in r.get("scan_hits", []) or []:
                rid = h.get("rule_id", "?")
                by_rule[rid] = by_rule.get(rid, 0) + 1
        out.append(
            {
                "name": f.stem,
                "size": len(rows),
                "by_source": by_source,
                "by_layer": by_layer,
                "by_rule": by_rule,
            }
        )
    return out


def frontier_from_summary(summary: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """由汇总行计算帕累托前沿（成本越低越好，残余风险越低越好）。"""
    pts = []
    for r in summary:
        pts.append(
            {
                "name": r.get("strategy", ""),
                "display_name": r.get("display_name", r.get("strategy", "")),
                "cost": float(r.get("c_ali", 0.0)),
                "risk": float(r.get("fnr", 0.0)),
                "suite": r.get("suite", ""),
                "acer": float(r.get("acer", 0.0)),
                "score": float(r.get("score", 0.0)),
                "n": r.get("n", 0),
            }
        )
    for i, p in enumerate(pts):
        dominated = any(
            o["cost"] <= p["cost"]
            and o["risk"] <= p["risk"]
            and (o["cost"] < p["cost"] or o["risk"] < p["risk"])
            for j, o in enumerate(pts)
            if i != j
        )
        pts[i]["dominated"] = dominated
    return pts


# --------------------------------------------------------------------------
# 运行时（门禁流水线 + 熔断 + 审计）
# --------------------------------------------------------------------------

_RUNTIME_LOCK = threading.Lock()
_RUNTIME: dict[str, Any] = {}


def get_runtime() -> dict[str, Any]:
    """惰性构建运行时（导入放在函数内，避免与并行开发模块的循环依赖）。"""
    with _RUNTIME_LOCK:
        if "pipeline" not in _RUNTIME:
            from .audit import AuditChain  # noqa: F401
            from .breaker import CircuitBreaker
            from .gates.pipeline import GatePipeline

            cfg = GateConfig.load()
            overrides, rater_report = load_rater_scores(cfg.expert_scores_dir)
            cells = build_matrix(
                overrides=overrides or None,
                weights=None,
                high_risk_threshold=cfg.high_risk_threshold,
            )
            chain = AuditChain(cfg.audit_log)
            breaker = CircuitBreaker(cfg, chain)
            pipeline = GatePipeline(cfg, cells)
            _RUNTIME.update(
                {
                    "config": cfg,
                    "cells": cells,
                    "rater_report": rater_report,
                    "audit": chain,
                    "breaker": breaker,
                    "pipeline": pipeline,
                    "verdicts": [],
                }
            )
        return _RUNTIME


def run_gate(mod: Modification, state: SystemState) -> dict[str, Any]:
    rt = get_runtime()
    pipeline = rt["pipeline"]
    breaker = rt["breaker"]
    audit = rt["audit"]
    config = rt["config"]

    audit.append(
        "propose",
        {
            "mod_id": mod.mod_id,
            "agent_id": mod.agent_id,
            "layer": mod.layer.value,
            "autonomy": mod.autonomy.value,
            "title": mod.title,
            "source": mod.source,
        },
    )
    if breaker.is_locked(mod):
        from .types import AdmissionAction, CostLedger, GateLevel, path_key

        pkey = path_key(mod.layer, mod.autonomy)
        until = breaker.locked_paths().get(pkey)
        verdict = {
            "mod": to_jsonable(mod),
            "action": AdmissionAction.REJECT.value,
            "gate_level": int(GateLevel.STATIC),
            "results": [],
            "cost": CostLedger().as_dict(),
            "cost_total": 0.0,
            "elapsed_s": 0.0,
            "detail": {
                "locked": True,
                "locked_path": pkey,
                "locked_until": until,
                "reason": f"路径「{pkey}」处于熔断锁定期（至 {until}），同类提案一律拒绝",
                "cost_absolute": {"elapsed_s": 0.0, "tokens": 0.0, "gpu_s": 0.0, "comp_cost": 0.0},
            },
            "breaker": None,
            "audit_hash": audit.head_hash(),
        }
        audit.append("verdict", verdict)
        rt["verdicts"].insert(0, verdict)
        rt["verdicts"] = rt["verdicts"][:200]
        return verdict

    gate_result = pipeline.run(mod, state)
    event = breaker.evaluate(mod, gate_result)
    verdict = {
        "mod": to_jsonable(mod),
        "action": gate_result.action.value,
        "gate_level": int(gate_result.level),
        "results": to_jsonable(gate_result.results),
        "cost": gate_result.cost.as_dict(),
        "cost_total": gate_result.cost.weighted_total(config.cost_weights or None),
        "elapsed_s": gate_result.elapsed_s,
        "detail": to_jsonable(gate_result.detail),
        "breaker": to_jsonable(event) if event else None,
        "audit_hash": audit.head_hash(),
    }
    audit.append("verdict", verdict)
    rt["verdicts"].insert(0, verdict)
    rt["verdicts"] = rt["verdicts"][:200]
    return verdict


# --------------------------------------------------------------------------
# API 处理
# --------------------------------------------------------------------------


def api_taxonomy() -> dict[str, Any]:
    rt = get_runtime()
    return {
        "matrix": matrix_to_rows(rt["cells"]),
        "ahp": ahp_consistency(),
        "raters": rt["rater_report"],
        "high_risk_threshold": rt["config"].high_risk_threshold,
    }


def api_state() -> dict[str, Any]:
    cfg = GateConfig.load()
    raw = _read_json(Path(cfg.state_path), None)
    if raw:
        return {"state": raw}
    try:
        from .mockdgm import MockSelfEvolvingFramework

        st = MockSelfEvolvingFramework(seed=0).initial_state()
        return {"state": to_jsonable(st)}
    except Exception:
        return {"state": {}}


def api_results() -> dict[str, Any]:
    summary = load_summaries()
    return {
        "summary": summary,
        "frontier": frontier_from_summary(summary),
        "raw_count": len(load_raw()),
    }


def api_audit() -> dict[str, Any]:
    rt = get_runtime()
    chain = rt["audit"]
    recs = chain.records()
    return {
        "verify": chain.verify(),
        "total": len(recs),
        "records": [
            {
                "seq": r.seq,
                "timestamp": r.timestamp,
                "kind": r.kind,
                "payload": r.payload,
                "prev_hash": r.prev_hash[:12],
                "this_hash": r.this_hash[:12],
            }
            for r in recs[-200:]
        ][::-1],
    }


def api_breakers() -> dict[str, Any]:
    rt = get_runtime()
    br = rt["breaker"]
    return {
        "locked_paths": br.locked_paths(),
        "history": [to_jsonable(e) for e in br.history()][::-1],
    }


def api_verdicts() -> dict[str, Any]:
    rt = get_runtime()
    return {"verdicts": rt.get("verdicts", [])}


def api_datasets() -> dict[str, Any]:
    return {"datasets": dataset_index()}


def api_dataset(name: str) -> dict[str, Any]:
    return {"name": name, "rows": load_dataset_file(name)}


def api_calibration() -> dict[str, Any]:
    p = DATA_DIR / "results" / "calibration.json"
    data = _read_json(p)
    return {"calibration": data}


def api_health() -> dict[str, Any]:
    try:
        rt = get_runtime()
        return {
            "ok": True,
            "version": __import__("ethgate").__version__,
            "config": rt["config"].to_dict(),
            "high_risk_cells": [c.key for c in rt["cells"] if c.is_high_risk],
        }
    except Exception as exc:  # pragma: no cover
        return {"ok": False, "error": str(exc), "traceback": traceback.format_exc()}


# --------------------------------------------------------------------------
# 进化直播（ethgate.live + ethgate.minievol）
# --------------------------------------------------------------------------


def _live_manager():
    from .live import manager

    return manager


def api_live_status() -> dict[str, Any]:
    from .minievol import api_configured, load_api_config

    mgr = _live_manager()
    api_cfg = load_api_config() if api_configured() else None
    cur = mgr.current.snapshot() if mgr.current else None
    return {
        "api_configured": bool(api_cfg),
        "provider": (api_cfg or {}).get("provider", ""),
        "model": (api_cfg or {}).get("model", ""),
        "current": cur,
        "sessions": mgr.saved_sessions()[:12],
    }


def api_live_sessions() -> dict[str, Any]:
    return {"sessions": _live_manager().saved_sessions()}


def api_live_session(session_id: str) -> dict[str, Any]:
    """取一场历史会话的全部事件（前端回放源）。"""
    from .live import LIVE_DIR

    safe = Path(session_id).name  # 防目录穿越
    f = LIVE_DIR / f"{safe}.jsonl"
    if not f.exists():
        return {"error": "session not found", "session_id": safe}
    events = []
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except Exception:
            continue
    return {"session_id": safe, "events": events}


def live_start(body: dict[str, Any]) -> dict[str, Any]:
    from .live import SessionOptions

    opts = SessionOptions(
        mode=str(body.get("mode", "auto")),
        generations=int(body.get("generations", 8)),
        pressure=bool(body.get("pressure", True)),
        speed=float(body.get("speed", 1.0)),
    )
    opts.generations = max(1, min(20, opts.generations))
    session = _live_manager().create(opts)
    return {"ok": True, "session": session.snapshot()}


def live_stop() -> dict[str, Any]:
    return _live_manager().stop_current()


def stream_live(self: "Handler", session_id: str) -> None:
    """SSE（chunked）：实时推送会话事件。会话结束后补发剩余事件并关闭流。"""
    import queue as _queue

    mgr = _live_manager()
    session = mgr.current
    if session is not None and session_id and session.session_id != session_id:
        session = None  # 指定了别的会话：只允许追当前场
    if session is None:
        self._send_json({"error": "no running session"}, 404)
        return

    q = session.subscribe()

    def _chunk(payload: bytes) -> bytes:
        return f"{len(payload):X}\r\n".encode("ascii") + payload + b"\r\n"

    self.send_response(200)
    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
    self.send_header("Cache-Control", "no-store")
    self.send_header("Transfer-Encoding", "chunked")
    self.end_headers()
    try:
        while True:
            try:
                event = q.get(timeout=15)
            except _queue.Empty:
                try:
                    self.wfile.write(_chunk(b": ping\n\n"))
                    self.wfile.flush()
                except (ConnectionAbortedError, BrokenPipeError, OSError):
                    break
                continue
            if event.get("type") == "__end__":
                payload = (
                    "data: "
                    + json.dumps(
                        {"type": "session_end", "session_id": session.session_id},
                        ensure_ascii=False,
                    )
                    + "\n\n"
                ).encode("utf-8")
                self.wfile.write(_chunk(payload))
                self.wfile.flush()
                break
            data = json.dumps(event, ensure_ascii=False, default=str)
            self.wfile.write(_chunk(f"data: {data}\n\n".encode("utf-8")))
            self.wfile.flush()
    except (ConnectionAbortedError, BrokenPipeError, OSError):
        pass  # 客户端断开属正常退出
    finally:
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except Exception:
            pass


ROUTES_GET: dict[str, Callable[[], Any]] = {
    "/api/health": api_health,
    "/api/taxonomy": api_taxonomy,
    "/api/state": api_state,
    "/api/results": api_results,
    "/api/audit": api_audit,
    "/api/breakers": api_breakers,
    "/api/verdicts": api_verdicts,
    "/api/datasets": api_datasets,
    "/api/calibration": api_calibration,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "ethgate/0.2"
    protocol_version = "HTTP/1.1"  # SSE 长连接需要；其余响应均带 Content-Length

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[ethgate] {fmt % args}\n")

    # -- 输出helper ---------------------------------------------------
    def _send_json(self, obj: Any, code: int = 200) -> None:
        body = json.dumps(to_jsonable(obj), ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self._send_json({"error": "not found", "path": str(path)}, 404)
            return
        ctype, _ = mimetypes.guess_type(str(path))
        if path.suffix == ".js":
            ctype = "application/javascript; charset=utf-8"
        elif path.suffix == ".css":
            ctype = "text/css; charset=utf-8"
        elif path.suffix == ".html":
            ctype = "text/html; charset=utf-8"
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    # -- 路由 ----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            if path == "/api/live/status":
                self._send_json(api_live_status())
                return
            if path == "/api/live/stream":
                qs = parse_qs(urlparse(self.path).query)
                stream_live(self, (qs.get("session") or [""])[0])
                return
            if path == "/api/live/sessions":
                self._send_json(api_live_sessions())
                return
            if path.startswith("/api/live/session/"):
                self._send_json(api_live_session(path.rsplit("/", 1)[-1]))
                return
            if path in ROUTES_GET:
                self._send_json(ROUTES_GET[path]())
                return
            if path.startswith("/api/dataset/"):
                self._send_json(api_dataset(path.rsplit("/", 1)[-1]))
                return
            if path.startswith("/static/"):
                rel = path[len("/static/") :]
                target = (WEB_DIR / rel).resolve()
                if WEB_DIR.resolve() in target.parents or target == WEB_DIR.resolve():
                    self._send_file(target)
                else:
                    self._send_json({"error": "forbidden"}, 403)
                return
            if path in ("/", "/index.html"):
                self._send_file(WEB_DIR / "index.html")
                return
            self._send_json({"error": "unknown route", "path": path}, 404)
        except Exception as exc:  # pragma: no cover
            self._send_json(
                {"error": str(exc), "traceback": traceback.format_exc()}, 500
            )

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b"{}"
            body = json.loads(raw.decode("utf-8") or "{}")
            if path == "/api/gate/check":
                mod = modification_from_dict(body.get("mod") or {})
                state = state_from_dict(body.get("state") or {})
                self._send_json(run_gate(mod, state))
                return
            if path == "/api/live/start":
                self._send_json(live_start(body))
                return
            if path == "/api/live/stop":
                self._send_json(live_stop())
                return
            if path == "/api/adjudicate":
                self._send_json(adjudicate(body))
                return
            if path == "/api/unlock":
                self._send_json(unlock_path(body))
                return
            self._send_json({"error": "unknown route", "path": path}, 404)
        except Exception as exc:  # pragma: no cover
            self._send_json(
                {"error": str(exc), "traceback": traceback.format_exc()}, 500
            )


def adjudicate(body: dict[str, Any]) -> dict[str, Any]:
    """人工裁决：记录裁决理由到审计链（哈希链，不可篡改）。"""
    rt = get_runtime()
    audit = rt["audit"]
    mod_id = body.get("mod_id", "")
    decision = body.get("decision", "")
    reason = body.get("reason", "")
    if not reason.strip():
        return {"ok": False, "error": "裁决理由为必填项"}
    rec = audit.append(
        "escalate",
        {
            "mod_id": mod_id,
            "decision": decision,
            "reason": reason,
            "reviewer": body.get("reviewer", "anonymous"),
        },
    )
    return {
        "ok": True,
        "audit_hash": rec.this_hash,
        "seq": rec.seq,
        "message": "裁决已写入哈希链审计记录",
    }


def unlock_path(body: dict[str, Any]) -> dict[str, Any]:
    """人工解除某条修改路径的熔断锁定（留审计痕迹）。"""
    rt = get_runtime()
    pkey = (body.get("path_key") or "").strip()
    reason = (body.get("reason") or "人工解除熔断锁定").strip()
    if not pkey:
        return {"ok": False, "error": "缺少 path_key"}
    ok = rt["breaker"].unlock(pkey, reason)
    return {
        "ok": ok,
        "path_key": pkey,
        "message": "已解除锁定" if ok else "该路径当前并未被锁定",
    }


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"伦理熔断控制台 → http://{host}:{port}")
    print("按 Ctrl+C 停止")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        srv.server_close()


def main() -> None:
    ap = argparse.ArgumentParser(description="伦理熔断控制台服务")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    serve(args.host, args.port)


if __name__ == "__main__":
    main()
