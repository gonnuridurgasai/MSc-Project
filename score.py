"""
score.py - score a method's predicted links against the ground-truth links.

A predicted link is a true positive (TP) if the same directed link
(from_record -> to_record) is in the ground truth, otherwise a false positive
(FP). A ground-truth link that was not predicted is a false negative (FN).

Also reports attack-step coverage: the share of attack events the method
included in its reconstruction.

Usage:
    python score.py predicted_links.csv gt_links.csv labelled.csv
"""
import csv
import sys


def read_links(path):
    with open(path, encoding="utf-8") as f:
        return {(r["from_record"], r["to_record"]) for r in csv.DictReader(f)}


def score(pred, gt, labelled_rows):
    tp = len(pred & gt)
    fp = len(pred - gt)
    fn = len(gt - pred)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    attack = {r["record_id"] for r in labelled_rows if r["label"] == "attack"}
    found = {x for link in pred for x in link}
    coverage = len(attack & found) / len(attack) if attack else 0.0
    return dict(tp=tp, fp=fp, fn=fn, precision=precision, recall=recall,
                f1=f1, coverage=coverage)


def main(pred_path, gt_path, labelled_path):
    with open(labelled_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    s = score(read_links(pred_path), read_links(gt_path), rows)
    print(f"TP={s['tp']}  FP={s['fp']}  FN={s['fn']}")
    print(f"Precision={s['precision']:.2f}  Recall={s['recall']:.2f}  "
          f"F1={s['f1']:.2f}  Coverage={s['coverage']:.2f}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: python score.py predicted_links.csv gt_links.csv labelled.csv")
    main(*sys.argv[1:])
