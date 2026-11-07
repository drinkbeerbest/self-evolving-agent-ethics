# -*- coding: utf-8 -*-
"""通过 GitHub API 推送本地领先的提交（增量、带父链）。"""
import base64
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = "drinkbeerbest/self-evolving-agent-ethics"


def token():
    return subprocess.run(["gh", "auth", "token"], capture_output=True, text=True).stdout.strip()


def api(method, path, body=None, retries=5):
    url = f"https://api.github.com{path}"
    data = json.dumps(body).encode() if body is not None else None
    last = None
    for i in range(retries):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {token()}")
        req.add_header("Accept", "application/vnd.github+json")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if raw.strip() else {})
        except urllib.error.HTTPError as e:
            if e.code in (409, 422):
                return e.code, e.read().decode()[:300]
            last = RuntimeError(f"HTTP {e.code}")
        except Exception as e:
            last = e
        time.sleep(3 + i * 3)
    raise last


def git(*args):
    return subprocess.run(["git", "-c", "core.quotepath=false", *args],
                          capture_output=True).stdout.decode("utf-8", "surrogateescape")


def push_commit(sha, parent):
    """上传一个提交的缺失 blob/tree/commit，返回远端 commit sha。"""
    # tree 直接用本地 ls-tree 的 SHA（blob 已在远端的会复用）
    out = git("ls-tree", "-r", sha, "-z")
    entries = []
    for item in out.split("\0"):
        if not item.strip():
            continue
        meta, path = item.split("\t", 1)
        mode, typ, bsha = meta.split()
        entries.append({"path": path, "mode": mode, "type": typ, "sha": bsha})
    s, tree = api("POST", f"/repos/{REPO}/git/trees", {"tree": entries})
    if s != 201:
        # 有缺失 blob：422 报告第一个，逐个补传后重试
        import re
        for _ in range(80):
            m = re.search(r"tree\.sha ([0-9a-f]{40}) is not a valid blob", str(tree))
            if not m:
                print("  tree 失败:", str(tree)[:200]); sys.exit(1)
            content = git("cat-file", "blob", m.group(1)).encode("utf-8", "surrogateescape")
            s2, b = api("POST", f"/repos/{REPO}/git/blobs",
                        {"content": base64.b64encode(content).decode("ascii"), "encoding": "base64"})
            if s2 != 201:
                print("  blob 失败:", s2, str(b)[:120]); sys.exit(1)
            s, tree = api("POST", f"/repos/{REPO}/git/trees", {"tree": entries})
            if s == 201:
                break
    body = {"message": git("log", "-1", "--format=%B", sha),
            "tree": tree["sha"], "parents": [parent] if parent else []}
    for field, val in (("author", git("log", "-1", "--format=%an|%ae|%aI", sha)),
                       ("committer", git("log", "-1", "--format=%cn|%ce|%cI", sha))):
        name, email, date = val.strip().split("|")
        body[field] = {"name": name, "email": email, "date": date}
    s, commit = api("POST", f"/repos/{REPO}/git/commits", body)
    if s != 201:
        print("  commit 失败:", s, str(commit)[:200]); sys.exit(1)
    return commit["sha"]


def main():
    s, ref = api("GET", f"/repos/{REPO}/git/ref/heads/main")
    remote_head = ref["object"]["sha"]
    local_head = git("rev-parse", "main").strip()
    if remote_head == local_head:
        print("远端已是最新:", remote_head); return 0
    # 本地领先提交序列（旧→新）
    todo = git("rev-list", "--reverse", f"{remote_head}..{local_head}").split()
    print(f"待推送 {len(todo)} 个提交: {todo}")
    head = remote_head
    for sha in todo:
        head = push_commit(sha, head)
        print(f"  已上传 {sha[:8]} -> {head[:8]}")
    s, _ = api("PATCH", f"/repos/{REPO}/git/refs/heads/main",
               {"sha": head, "force": False})
    print("ref 更新:", s)
    return 0 if s in (200, 422) else 1


if __name__ == "__main__":
    sys.exit(main())
