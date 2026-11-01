"""哈希链式审计日志（支撑 I2 审计完备性：任一历史状态可重建）。

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
        try:
            import msvcrt  # type: ignore

            msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        except Exception:
            try:
                import fcntl  # type: ignore

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            except Exception:
                pass
        yield
    finally:
        if fh is not None:
            try:
                import msvcrt  # type: ignore

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            except Exception:
                pass
            fh.close()


class AuditChain:
    """追加式的哈希链审计日志。"""

    #: 链头读取的尾部窗口（字节）。链头只需要最后一条记录，
    #: 全量重读在链增长到数万条后会让每次追加重读整个文件。
    _TAIL_BYTES = 256 * 1024

    def __init__(self, log_path: str | Path):
        self.path = Path(log_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._records: list[AuditRecord] = []
        self._cache_key: tuple[int, int] | None = None  # (mtime_ns, size)
        self._load()

    # -- 持久化 ---------------------------------------------------------
    def _load(self) -> None:
        self._records = list(self._read_all())

    def _stat(self) -> tuple[int, int] | None:
        try:
            st = self.path.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _read_all(self) -> list[AuditRecord]:
        """全量读取（带 mtime+size 缓存：追加式文件内容相同时无需重解析）。"""
        key = self._stat()
        if key is None:
            self._records = []
            self._cache_key = None
            return []
        if key == self._cache_key and self._records:
            return self._records
        out: list[AuditRecord] = []
        try:
            text = self.path.read_text(encoding="utf-8")
        except Exception:
            return self._records
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(AuditRecord(**json.loads(line)))
            except Exception:
                continue
        self._records = out
        self._cache_key = key
        return out

    def _disk_head(self) -> tuple[int, str]:
        """从磁盘读出真实链头：(下一条 seq, 上一条 this_hash)。

        只读文件尾部：append-only 文件的最后一条记录就是链头，
        不必解析全文件（数万条记录时全量重读会让每次追加变成秒级）。
        """
        if not self.path.exists():
            return 0, GENESIS
        try:
            with self.path.open("rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - self._TAIL_BYTES))
                tail = f.read().decode("utf-8", "ignore")
        except OSError:
            recs = self._read_all()
            if not recs:
                return 0, GENESIS
            return int(recs[-1].seq) + 1, str(recs[-1].this_hash)
        lines = [ln for ln in tail.splitlines() if ln.strip()]
        if not lines:
            return 0, GENESIS
        try:
            last = json.loads(lines[-1])
            return int(last["seq"]) + 1, str(last["this_hash"])
        except Exception:
            # 尾部窗口恰好截断在行中间等异常情况：退回全量读取
            recs = self._read_all()
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
            this = AuditRecord.compute_hash(seq, ts, kind, payload, prev)
            rec = AuditRecord(seq=seq, timestamp=ts, kind=kind, payload=payload,
                              prev_hash=prev, this_hash=this)
            line = json.dumps(rec.__dict__, ensure_ascii=False, default=_json_default)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._records.append(rec)
            self._cache_key = self._stat()
            return rec

    # -- 查询 -----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._read_all())

    def records(self, kind: str | None = None) -> list[AuditRecord]:
        recs = self._read_all()
        if kind is None:
            return recs
        return [r for r in recs if r.kind == kind]

    def verify(self) -> dict[str, Any]:
        """校验链完整性（以磁盘内容为准）。"""
        recs = self._read_all()
        prev = GENESIS
        for i, r in enumerate(recs):
            expect = AuditRecord.compute_hash(
                r.seq, r.timestamp, r.kind, r.payload, prev
            )
            if r.prev_hash != prev or r.this_hash != expect:
                return {
                    "valid": False,
                    "broken_at_seq": i,
                    "total": len(recs),
                }
            prev = r.this_hash
        return {"valid": True, "broken_at_seq": None, "total": len(recs)}

    def reconstruct(self, seq: int) -> dict[str, Any] | None:
        """按 seq 重建一条记录（I2 的可重建性演示）。"""
        for r in self._read_all():
            if r.seq == seq:
                return {
                    "seq": r.seq,
                    "timestamp": r.timestamp,
                    "kind": r.kind,
                    "payload": r.payload,
                    "prev_hash": r.prev_hash,
                    "this_hash": r.this_hash,
                }
        return None

    def head_hash(self) -> str:
        recs = self._read_all()
        return recs[-1].this_hash if recs else GENESIS
