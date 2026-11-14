"""
label_ground_truth.py - label which Sysmon events belong to the attack.

Uses the orchestrator's ground_truth.json (anchor process ID + per-step time
windows) and the normalised events CSV. No marker strings are used: attack
events are found by process ancestry from the orchestrator's process.

Labels written to every event:
    attack   - caused by an attack step (with its step number)
    harness  - bookkeeping by the Invoke-AtomicTest framework itself
               (hostname.exe / whoami.exe run before each test), not attack
    benign   - everything else

Also writes the ground-truth LINKS (directed edges between attack events),
which is what the correlation methods are scored against.

Usage:
    python label_ground_truth.py events.csv ground_truth.json labelled.csv gt_links.csv
"""
import csv
import json
import re
import sys
from datetime import datetime, timezone

HARNESS_IMAGES = {"hostname.exe", "whoami.exe"}


def ts(value):
    """Parse Sysmon 'YYYY-MM-DD HH:MM:SS.fff' or ISO-8601 into UTC datetime."""
    value = value.strip().replace("Z", "+00:00")
    if "T" in value:
        # trim sub-microsecond digits that fromisoformat rejects
        value = re.sub(r"(\.\d{6})\d+", r"\1", value)
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)


def short(path):
    return path.replace("/", "\\").split("\\")[-1].lower()


def step_for(t, steps):
    for s in steps:
        if s["start"] <= t <= s["end"]:
            return s["step"]
    return None


def label(rows, gt):
    anchor = str(gt["anchor_pid"])
    steps = [{"step": s["step"], "start": ts(s["start_utc"]), "end": ts(s["end_utc"])}
             for s in gt["steps"]]
    attack_guids = {}          # process_guid -> step
    links = []                 # (from_record, to_record, kind)
    proc_record = {}           # process_guid -> record_id of its creation event

    for r in rows:
        r["label"], r["step"], r["note"] = "benign", "", ""
        t = ts(r["utc_time"])

        if r["event_type"] == "process_create":
            img = short(r["image"])
            if r["parent_pid"] == anchor and img in HARNESS_IMAGES:
                r["label"] = "harness"
                continue
            if r["parent_pid"] == anchor:                     # a step's root process
                st = step_for(t, steps)
                if st is not None:
                    r["label"], r["step"] = "attack", st
                    attack_guids[r["process_guid"]] = st
                    proc_record[r["process_guid"]] = r["record_id"]
                    r["note"] = "step root (child of orchestrator)"
                continue
            parent = r["parent_process_guid"]
            if parent in attack_guids:                        # descendant of an attack process
                st = attack_guids[parent]
                r["label"], r["step"] = "attack", st
                attack_guids[r["process_guid"]] = st
                proc_record[r["process_guid"]] = r["record_id"]
                links.append((proc_record[parent], r["record_id"], "created process"))

        elif r["process_guid"] in attack_guids:              # file / registry / network by an attack process
            st = attack_guids[r["process_guid"]]
            r["label"], r["step"] = "attack", st
            kind = {"file_create": "created file", "registry_set": "set registry",
                    "network_connect": "connected"}.get(r["event_type"], r["event_type"])
            links.append((proc_record[r["process_guid"]], r["record_id"], kind))

    # Indirect effect: a scheduled task file written by the Task Scheduler service
    # (svchost.exe) on behalf of an attack schtasks.exe /Create /TN <name>.
    for r in rows:
        if r["label"] != "attack" or short(r["image"]) != "schtasks.exe":
            continue
        m = re.search(r"/TN\s+\"?([^\s\"]+)", r["command_line"], re.I)
        if not m:
            continue
        task = m.group(1).lower()
        for f in rows:
            if (f["event_type"] == "file_create" and short(f["image"]) == "svchost.exe"
                    and f["target_filename"].lower().endswith("\\tasks\\" + task)
                    and ts(f["utc_time"]) >= ts(r["utc_time"])):
                f["label"], f["step"] = "attack", r["step"]
                f["note"] = "indirect: written by Task Scheduler service, no Sysmon parent link"
                links.append((r["record_id"], f["record_id"], "created task (indirect)"))
    return links


def main(events_csv, gt_json, out_csv, links_csv):
    with open(events_csv, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    with open(gt_json, encoding="utf-8-sig") as f:
        gt = json.load(f)
    links = label(rows, gt)

    fields = list(rows[0].keys())
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    with open(links_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["from_record", "to_record", "relation"])
        w.writerows(links)

    by = {}
    for r in rows:
        by[r["label"]] = by.get(r["label"], 0) + 1
    print(f"Run {gt['run_id']}: {len(rows)} events -> " +
          ", ".join(f"{k}: {v}" for k, v in sorted(by.items())))
    print(f"Ground-truth links: {len(links)}")
    for st in sorted({r['step'] for r in rows if r['label'] == 'attack'}, key=int):
        names = [f"{r['record_id']}:{short(r['image']) if r['event_type']=='process_create' else r['event_type']}"
                 for r in rows if r["label"] == "attack" and r["step"] == st]
        print(f"  step {st}: " + " -> ".join(names))
    missing = {s["step"] for s in gt["steps"]} - {int(r["step"]) for r in rows if r["label"] == "attack"}
    if missing:
        print(f"WARNING: no attack events found for step(s) {sorted(missing)}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("usage: python label_ground_truth.py events.csv ground_truth.json labelled.csv gt_links.csv")
    main(*sys.argv[1:])
