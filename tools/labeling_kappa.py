"""标注一致性计算：Fleiss' κ + 扫描器规则 vs 人工多数意见。

前置：tools/export_corpus.py 生成的 data/corpus/labeling_sheet.csv，
     且三位组员已独立填完 rater_1 / rater_2 / rater_3 列（dangerous / safe）。

输出
----
* Fleiss' κ（三人针对二分类的一致性；κ>0.6 为"显著一致"的常用门槛）
* 人工多数意见 vs 扫描器规则的混淆矩阵与 precision / recall
* 结论话术：把"我们自己定义危险"升级为"规则经三人独立标注验证"
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHEET = ROOT / "data" / "corpus" / "labeling_sheet.csv"


def fleiss_kappa(mat: list[list[int]]) -> float:
    """mat[i] = [n_dangerous, n_safe]（每行人数相同）。"""
    n_rows = len(mat)
    if n_rows == 0:
        return 0.0
    n_per = sum(mat[0])
    if n_per < 2:
        return 0.0
    p_i = [(sum(c * (c - 1) for c in row)) / (n_per * (n_per - 1)) for row in mat]
    p_bar = sum(p_i) / n_rows
    cat_totals = [sum(row[j] for row in mat) for j in range(len(mat[0]))]
    e_bar = sum((t / (n_rows * n_per)) ** 2 for t in cat_totals)
    if abs(1 - e_bar) < 1e-12:
        return 1.0
    return (p_bar - e_bar) / (1 - e_bar)


def main() -> int:
    if not SHEET.exists():
        print("缺少标注工作表：先运行 tools/export_corpus.py")
        return 1
    rows = list(csv.DictReader(SHEET.open(encoding="utf-8-sig")))
    raters = ["rater_1", "rater_2", "rater_3"]
    filled = [r for r in rows if all(r[c].strip().lower() in ("dangerous", "safe") for c in raters)]
    if len(filled) < 10:
        print(f"有效标注行不足（{len(filled)}/{len(rows)}）——请三位组员先完成独立标注")
        return 1

    mat = [[0, 0] for _ in filled]
    for i, r in enumerate(filled):
        for c in raters:
            mat[i][0 if r[c].strip().lower() == "dangerous" else 1] += 1
    kappa = fleiss_kappa(mat)

    tp = fp = tn = fn = 0
    for r in filled:
        human = sum(1 for c in raters if r[c].strip().lower() == "dangerous") >= 2
        scanner = r["scanner_label"].strip().lower() == "dangerous"
        if scanner and human:
            tp += 1
        elif scanner and not human:
            fp += 1
        elif not scanner and human:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    report = {
        "labeled_rows": len(filled),
        "raters": 3,
        "fleiss_kappa": round(kappa, 3),
        "kappa_interpretation": (
            "几乎完全一致 (0.81-1.0)" if kappa > 0.8 else
            "高度一致 (0.61-0.8)" if kappa > 0.6 else
            "中度一致 (0.41-0.6)" if kappa > 0.4 else
            "一致性偏弱（需复议标注标准）"),
        "scanner_vs_human": {
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "confusion": {"true_positive": tp, "false_positive": fp,
                          "false_negative": fn, "true_negative": tn},
        },
    }
    (ROOT / "data" / "corpus" / "kappa_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
