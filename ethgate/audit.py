"""哈希链式审计日志（支撑 I2 的事件留痕与完整性校验）。

事件检索不等于任意历史状态重建；完整重建还需要可信快照及可应用的变更载荷。

每条记录包含 prev_hash 与 this_hash，形成链。任何一条被篡改，
后续所有记录的 this_hash 校验都会失败。

审计事件类型：
  propose   一次自我修改提案
  verdict   准入判定结果
  breaker   熔断事件
  rollback  回滚执行
  escalate  上报人工裁决

并发安全
--------
实验运行器、CLI、服务进程可能同时写同一个审计文件。
本实现坚持两条规则：
  1. **只追加，不重写**——整文件重写会让后写进程覆盖先写进程的记录，
     直接导致链断裂；改成 O_APPEND 后，先写者永不被抹掉。
  2. **链头以磁盘为准**——每次追加前重新读磁盘上的最后一条记录来确定
     seq 与 prev_hash，不信任内存里的旧值。
另加一把跨进程文件锁，避免两次追加交错。
"""
from __future__ import annotations

import json
from copy import deepcopy
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .types import AuditRecord, _json_default

GENESIS = "0" * 64


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """跨进程排他锁（Windows 用 msvcrt，POSIX 用 fcntl）。"""
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = None
    try:
        fh = open(lock_path, "a+b")
        if os.name == "nt":
            import msvcrt

            # a+b 默认定位到末尾；所有写入者必须锁住同一个字节。
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        # 获取锁失败必须中止写入，不能退化为无锁追加。
        yield
    finally:
        if fh is not None:
            try:
                if os.name == "nt":
                    import msvcrt

                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            fh.close()


class AuditChain:
    """追加式的哈希链审计日志。"""

    def __init__(self, log_path: str | Path):
        self.path = Path(log_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._records: list[AuditRecord] = []
        self._cache_key: tuple[int, int] | None = None  # (mtime_ns, size)
        self._read_error: dict[str, Any] | None = None
        self._load()

    # -- 持久化 ---------------------------------------------------------
    def _load(self) -> None:
        self._records = list(self._read_all())

    def _stat(self) -> tuple[int, int] | None:
        try:
            st = self.path.stat()
            return (st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            return None

    def _read_all(self, *, force: bool = False) -> list[AuditRecord]:
        with self._lock:
            try:
                # 与写入共用文件锁，避免把尚未写完的一行误报为损坏。
                with _file_lock(self.path):
                    return self._read_disk(force=force)
            except OSError as exc:
                self._read_error = {"broken_at_seq": 0, "line": None,
                                    "reason": f"审计文件无法锁定：{type(exc).__name__}"}
                self._records = []
                self._cache_key = None
                return []

    def _read_disk(self, *, force: bool = False) -> list[AuditRecord]:
        """全量读取（带 mtime+size 缓存：追加式文件内容相同时无需重解析）。"""
        try:
            key = self._stat()
        except OSError as exc:
            self._read_error = {"broken_at_seq": 0, "line": None,
                                "reason": f"审计文件无法访问：{type(exc).__name__}"}
            self._records = []
            self._cache_key = None
            return []
        if key is None:
            self._records = []
            self._cache_key = None
            self._read_error = None
            return []
        if not force and key == self._cache_key:
            return self._records
        out: list[AuditRecord] = []
        self._read_error = None
        try:
            text = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            self._read_error = {"broken_at_seq": 0, "line": None,
                                "reason": f"审计文件无法读取：{type(exc).__name__}"}
            self._records = []
            self._cache_key = None
            return []
        prev = GENESIS
        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = AuditRecord(**json.loads(line))
                if type(rec.seq) is not int or rec.seq != len(out):
                    raise ValueError("记录序号不连续")
                expect = AuditRecord.compute_hash(
                    rec.seq, rec.timestamp, rec.kind, rec.payload, prev
                )
                if rec.prev_hash != prev or rec.this_hash != expect:
                    raise ValueError("记录哈希不匹配")
            except (TypeError, ValueError, KeyError) as exc:
                self._read_error = {"broken_at_seq": len(out), "line": line_no,
                                    "reason": f"审计记录损坏：{type(exc).__name__}"}
                break
            out.append(rec)
            prev = rec.this_hash
        self._records = out
        self._cache_key = key
        return out

    def _disk_head(self) -> tuple[int, str]:
        """从磁盘读出真实链头：(下一条 seq, 上一条 this_hash)。

        自身连续追加命中缓存；其他写入者改变文件后重新读取并校验，
        防止内存漏记录或接在损坏记录后继续写入。
        """
        # append 已持有进程内与文件锁，不能重复获取文件锁。
        recs = self._read_disk()
        if self._read_error:
            raise ValueError("审计链损坏或不可读取，已停止追加")
        if not recs:
            return 0, GENESIS
        return int(recs[-1].seq) + 1, str(recs[-1].this_hash)

    def _flush(self) -> None:
        """兼容旧接口：重写整个文件（仅在明确需要时使用）。"""
        with self.path.open("w", encoding="utf-8") as f:
            for r in self._records:
                f.write(json.dumps(r.__dict__, ensure_ascii=False, default=_json_default) + "\n")

    # -- 追加 -----------------------------------------------------------
    def append(self, kind: str, payload: dict[str, Any]) -> AuditRecord:
        with self._lock, _file_lock(self.path):
            seq, prev = self._disk_head()
            ts = time.time()
            # 缓存与落盘内容均使用独立的 JSON 快照，调用者后续修改不能污染缓存。
            snapshot = json.loads(json.dumps(payload, ensure_ascii=False, default=_json_default))
            this = AuditRecord.compute_hash(seq, ts, kind, snapshot, prev)
            rec = AuditRecord(seq=seq, timestamp=ts, kind=kind, payload=snapshot,
                              prev_hash=prev, this_hash=this)
            line = json.dumps(rec.__dict__, ensure_ascii=False, default=_json_default)
            # 外部导入的有效 JSONL 最后一行也可能没有换行。
            separator = ""
            if self.path.exists() and self.path.stat().st_size:
                with self.path.open("rb") as existing:
                    existing.seek(-1, os.SEEK_END)
                    if existing.read(1) != b"\n":
                        separator = "\n"
            with self.path.open("a", encoding="utf-8") as f:
                f.write(separator + line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._records.append(rec)
            self._cache_key = self._stat()
            return deepcopy(rec)

    # -- 查询 -----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._read_all())

    def records(self, kind: str | None = None) -> list[AuditRecord]:
        recs = self._read_all()
        if kind is None:
            return deepcopy(recs)
        return deepcopy([r for r in recs if r.kind == kind])

    def verify(self) -> dict[str, Any]:
        """校验链完整性（以磁盘内容为准）。"""
        with self._lock:
            return self._verify()

    def _verify(self) -> dict[str, Any]:
        # 校验不能仅依赖 mtime/size 缓存：同长度篡改也必须被发现。
        recs = self._read_all(force=True)
        checked_at = time.time()
        if self._read_error:
            return {"valid": False, "total": len(recs), "checked_at": checked_at,
                    **self._read_error}
        prev = GENESIS
        for i, r in enumerate(recs):
            expect = AuditRecord.compute_hash(
                r.seq, r.timestamp, r.kind, r.payload, prev
            )
            if r.prev_hash != prev or r.this_hash != expect:
                return {
                    "valid": False,
                    "broken_at_seq": i,
                    "total": len(recs), "checked_at": checked_at,
                }
            prev = r.this_hash
        return {"valid": True, "broken_at_seq": None, "total": len(recs),
                "checked_at": checked_at}

    def reconstruct(self, seq: int) -> dict[str, Any] | None:
        """按 seq 检索一条审计事件；不声称还原完整系统状态。"""
        for r in self._read_all():
            if r.seq == seq:
                return {
                    "seq": r.seq,
                    "timestamp": r.timestamp,
                    "kind": r.kind,
                    "payload": deepcopy(r.payload),
                    "prev_hash": r.prev_hash,
                    "this_hash": r.this_hash,
                }
        return None

    def head_hash(self) -> str:
        recs = self._read_all()
        return recs[-1].this_hash if recs else GENESIS
