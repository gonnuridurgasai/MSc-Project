"""
run_pipeline.py - analyse one lab run with a single command.

Steps: normalise the Sysmon log -> label the ground truth -> run Method A (PIDs)
and Method A' (GUIDs) -> score both -> draw the comparison picture.
All outputs are written into an "analysis" folder inside the run folder.

Usage:
    python run_pipeline.py <run_folder> [--seed <record_id>] [--dt 5]

If --seed is not given, the alert is the first Registry Run-key event in the run.
"""
import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import normalise
import label_ground_truth
import method_a
import method_b
import score
import draw_reconstruction


def write_links(path, links):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["from_record", "to_record"])
        w.writerows(sorted(links))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_folder")
    ap.add_argument("--seed", default=None)
    ap.add_argument("--dt", type=float, default=5.0)
    a = ap.parse_args()

    run = os.path.abspath(a.run_folder)
    out = os.path.join(run, "analysis")
    os.makedirs(out, exist_ok=True)
    p = lambda name: os.path.join(out, name)

    print(f"== Analysing {os.path.basename(run)} ==")
    normalise.normalise(os.path.join(run, "sysmon.xml"), p("events.csv"))
    label_ground_truth.main(p("events.csv"), os.path.join(run, "ground_truth.json"),
                            p("labelled.csv"), p("gt_links.csv"))

    with open(p("labelled.csv"), encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    seed = a.seed or next((r["record_id"] for r in rows
                           if r["event_type"] == "registry_set"
                           and "\\currentversion\\run" in r["target_object"].lower()), None)
    if not seed:
        sys.exit("No seed given and no Run-key event found; pass --seed <record_id>.")
    print(f"Alert (seed event): {seed}")

    gt = score.read_links(p("gt_links.csv"))
    results = {}
    for mode, name, fname in (("pid", "Method A (PIDs)", "A_pid.csv"),
                              ("guid", "Method A' (GUIDs)", "A_guid.csv")):
        _, links = method_a.reconstruct(rows, seed, mode, a.dt)
        write_links(p(fname), links)
        s = score.score(links, gt, rows)
        results[name] = s
        print(f"{name:<18} precision {s['precision']:.2f}  recall {s['recall']:.2f}  "
              f"F1 {s['f1']:.2f}  (correct {s['tp']}, wrong {s['fp']}, missed {s['fn']})")

    _, links = method_b.reconstruct(rows, seed)
    write_links(p("B_prov.csv"), links)
    s = score.score(links, gt, rows)
    results["Method B (provenance)"] = s
    print(f"{'Method B (prov.)':<18} precision {s['precision']:.2f}  recall {s['recall']:.2f}  "
          f"F1 {s['f1']:.2f}  (correct {s['tp']}, wrong {s['fp']}, missed {s['fn']})")

    with open(p("scores.json"), "w", encoding="utf-8") as f:
        json.dump({"seed": seed, "dt": a.dt, "results": results}, f, indent=2)

    draw_reconstruction.main(p("labelled.csv"), p("gt_links.csv"), p("reconstruction.png"),
                             p("A_pid.csv"), "Method A (PIDs)", p("A_guid.csv"), "Method A' (GUIDs)",
                             p("B_prov.csv"), "Method B (provenance)")
    print(f"All outputs saved in: {out}")
    if os.name == "nt":
        os.startfile(p("reconstruction.png"))   # open the picture on Windows


if __name__ == "__main__":
    main()
