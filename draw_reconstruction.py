"""
draw_reconstruction.py - picture of each method's rebuilt attack vs the answer key.

Green arrow  = correct link (in the ground truth)
Red arrow    = wrong link (predicted, not in the ground truth)
Grey dashed  = missed link (in the ground truth, not predicted)
Node colour  = attack event (orange) or other event (grey)

Usage:
    python draw_reconstruction.py labelled.csv gt_links.csv out.png A_pid.csv "Method A (PIDs)" A_guid.csv "Method A' (GUIDs)"
"""
import csv
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import networkx as nx


def read_links(path):
    with open(path, encoding="utf-8") as f:
        return {(r["from_record"], r["to_record"]) for r in csv.DictReader(f)}


def node_label(r):
    if r["event_type"] == "process_create":
        name = r["image"].split("\\")[-1]
    elif r["event_type"] == "file_create":
        name = "file: " + r["target_filename"].split("\\")[-1][:18]
    elif r["event_type"] == "registry_set":
        name = "Run key set"
    else:
        name = r["event_type"]
    return f"{r['record_id']}\n{name}"


def layout(rows):
    """Columns follow time order; attack events on the top rows, others below."""
    pos, col = {}, {}
    order = [r["record_id"] for r in rows]
    for i, rid in enumerate(order):
        col[rid] = i
    for r in rows:
        rid = r["record_id"]
        y = 1.0 if r["label"] == "attack" else 0.0
        pos[rid] = (col[rid], y + (0.35 if col[rid] % 2 else 0))
    return pos


def draw(ax, rows, gt, pred, title):
    g = nx.DiGraph()
    used = {n for link in gt | pred for n in link}
    rows = [r for r in rows if r["record_id"] in used]
    for r in rows:
        g.add_node(r["record_id"])
    pos = layout(rows)
    colours = ["#f4a259" if r["label"] == "attack" else "#d3d3d3" for r in rows]
    nx.draw_networkx_nodes(g, pos, nodelist=[r["record_id"] for r in rows],
                           node_color=colours, node_size=1500, ax=ax, edgecolors="#555")
    nx.draw_networkx_labels(g, pos, labels={r["record_id"]: node_label(r) for r in rows},
                            font_size=7, ax=ax)
    for edges, colour, style in ((pred & gt, "#2e8b57", "solid"),
                                 (pred - gt, "#d62728", "solid"),
                                 (gt - pred, "#999999", "dashed")):
        nx.draw_networkx_edges(g, pos, edgelist=list(edges), edge_color=colour, style=style,
                               width=2, arrows=True, arrowsize=16, ax=ax,
                               connectionstyle="arc3,rad=0.15", node_size=1500)
    tp, fp, fn = len(pred & gt), len(pred - gt), len(gt - pred)
    p = tp / (tp + fp) if tp + fp else 0
    rc = tp / (tp + fn) if tp + fn else 0
    ax.set_title(f"{title}\ncorrect {tp}  wrong {fp}  missed {fn}  |  precision {p:.2f}  recall {rc:.2f}",
                 fontsize=10)
    ax.axis("off")


def main(labelled, gt_path, out, *pairs):
    with open(labelled, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    gt = read_links(gt_path)
    methods = list(zip(pairs[0::2], pairs[1::2]))
    fig, axes = plt.subplots(len(methods), 1, figsize=(13, 4.2 * len(methods)))
    if len(methods) == 1:
        axes = [axes]
    for ax, (path, title) in zip(axes, methods):
        draw(ax, rows, gt, read_links(path), title)
    legend = [Line2D([0], [0], color="#2e8b57", lw=2, label="correct link"),
              Line2D([0], [0], color="#d62728", lw=2, label="wrong link"),
              Line2D([0], [0], color="#999999", lw=2, ls="--", label="missed link"),
              Line2D([0], [0], marker="o", color="w", markerfacecolor="#f4a259", markersize=12, label="attack event"),
              Line2D([0], [0], marker="o", color="w", markerfacecolor="#d3d3d3", markersize=12, label="other event")]
    fig.legend(handles=legend, loc="lower center", ncol=5, frameon=False)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(out, dpi=150)
    print(f"Saved {out}")


if __name__ == "__main__":
    if len(sys.argv) < 6 or (len(sys.argv) - 4) % 2:
        sys.exit(__doc__)
    main(*sys.argv[1:])
