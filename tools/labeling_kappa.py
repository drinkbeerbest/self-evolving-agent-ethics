"""合并三份独立盲标，通过稳定 ID 关联机器标签；无人工标签时只报告待标注。"""
from __future__ import annotations
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "data" / "corpus"
RATERS = ("rater_1", "rater_2", "rater_3")
VALID_LABELS = {"dangerous", "safe"}


def fleiss_kappa(mat: list[list[int]]) -> float | None:
    """单一类别使期望一致率为 1 时 κ 无定义，不能记为完美一致。"""
    if not mat:
        return None
    n_per = sum(mat[0])
    if n_per < 2 or any(len(row) != 2 or sum(row) != n_per for row in mat):
        raise ValueError("每条提案必须具有相同且至少两位标注者")
    observed = sum(sum(c * (c - 1) for c in row) / (n_per * (n_per - 1)) for row in mat) / len(mat)
    expected = sum((sum(row[j] for row in mat) / (len(mat) * n_per)) ** 2 for j in (0, 1))
    return None if abs(1 - expected) < 1e-12 else (observed - expected) / (1 - expected)


def _rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    ids = [row.get("id") for row in rows]
    if any(not mid for mid in ids) or len(ids) != len(set(ids)):
        raise ValueError(f"{path.name} 存在空 ID 或重复提案 ID")
    return rows


def calculate_report(corpus: Path) -> dict:
    master = _rows(corpus / "labeling_sheet.csv")
    if not master:
        raise ValueError("缺少非空标注工作表；先运行 tools/export_corpus.py")
    merged = {row["id"]: {r: (row.get(r) or "").strip().lower() for r in RATERS} for row in master}
    for rater in RATERS:
        for row in _rows(corpus / f"{rater}.csv"):
            mid, label = row["id"], (row.get("label") or "").strip().lower()
            if mid not in merged:
                raise ValueError(f"{rater}.csv 存在未知提案 ID: {mid}")
            if label and label not in VALID_LABELS:
                raise ValueError(f"{rater}.csv {mid} 的标签必须是 dangerous/safe")
            if label and merged[mid][rater] and label != merged[mid][rater]:
                raise ValueError(f"{mid} 的 {rater} 独立表与合并表标签冲突")
            if label:
                merged[mid][rater] = label
    for mid, labels in merged.items():
        if any(value and value not in VALID_LABELS for value in labels.values()):
            raise ValueError(f"{mid} 含无效标签")
    complete = {mid: labels for mid, labels in merged.items() if all(labels[r] in VALID_LABELS for r in RATERS)}
    report = {"schema": "ethgate.labeling/v2", "status": "pending", "sheet_rows": len(master),
              "labeled_rows": len(complete), "raters": 3, "fleiss_kappa": None,
              "independent_human_validation": False,
              "message": "人工独立标注尚未完成；未生成或推断任何人工标签。"}
    if len(complete) < 10:
        return report
    if not (corpus / "proposals.jsonl").exists():
        raise ValueError("缺少用于 ID 关联的 proposals.jsonl")
    machine = {}
    for line in (corpus / "proposals.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        proposal = json.loads(line)
        mid, label = proposal.get("annotation_id"), proposal.get("scanner_dangerous")
        if mid and isinstance(label, bool):
            if mid in machine and machine[mid] != label:
                raise ValueError(f"同一证据 ID {mid} 存在冲突机器标签；需先核查完整证据")
            machine[mid] = label
    mat = [[sum(labels[r] == "dangerous" for r in RATERS), sum(labels[r] == "safe" for r in RATERS)]
           for labels in complete.values()]
    kappa = fleiss_kappa(mat)
    tp = fp = tn = fn = 0
    for mid, labels in complete.items():
        if mid not in machine:
            continue
        human = sum(labels[r] == "dangerous" for r in RATERS) >= 2
        if machine[mid] and human:
            tp += 1
        elif machine[mid]:
            fp += 1
        elif human:
            fn += 1
        else:
            tn += 1
    report.update(status="complete" if len(complete) == len(master) else "partial",
                  independent_human_validation=True, fleiss_kappa=kappa,
                  message="仅基于已完成的独立人工标签统计；样本有限，不能证明完整覆盖。",
                  scanner_vs_human={"evaluated_rows": tp + fp + tn + fn,
                                    "unmatched_rows": len(complete) - tp - fp - tn - fn,
                                    "precision": tp / (tp + fp) if tp + fp else None,
                                    "recall": tp / (tp + fn) if tp + fn else None,
                                    "confusion": {"true_positive": tp, "false_positive": fp,
                                                  "false_negative": fn, "true_negative": tn}})
    return report


def main() -> int:
    try:
        report = calculate_report(CORPUS)
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"标注数据有误：{exc}")
        return 1
    (CORPUS / "kappa_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
