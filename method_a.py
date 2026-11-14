"""
method_a.py - Method A: temporal/entity-based correlation (and A' with GUIDs).

Starting from a seed event (the "alert"), repeatedly adds any event that
  * happens within DT seconds of an event already in the reconstruction, and
  * shares an identifier with it: process ID, parent process ID, or file path,
  * for the same user (used only as a filter, since most activity shares a user).
Each added event is linked to the event it matched, directed earlier -> later.

--ids pid   Method A  : process identity from PIDs (which Windows reuses)
--ids guid  Method A' : process identity from Sysmon ProcessGuids (never reused)

The method never sees the ground-truth labels.

Usage:
    python method_a.py labelled.csv --seed <record_id> [--ids pid|guid] [--dt 5] [--out links.csv]
"""
import argparse
import csv
from datetime import datetime

NULL_GUID = "{00000000-0000-0000-0000-000000000000}"


def ts(v):
    return datetime.strptime(v.strip(), "%Y-%m-%d %H:%M:%S.%f")


def identifiers(r, mode):
    """The set of identifiers an event can be linked by."""
    ids = set()
    if mode == "pid":
        if r["pid"]:
            ids.add(("proc", r["pid"]))
        if r["parent_pid"]:
            ids.add(("proc", r["parent_pid"]))
    else:  # guid
        if r["process_guid"]:
            ids.add(("proc", r["process_guid"]))
        if r["parent_process_guid"] and r["parent_process_guid"] != NULL_GUID:
            ids.add(("proc", r["parent_process_guid"]))
    for f in ("target_filename", "target_object", "dest_ip"):
        if r.get(f):
            ids.add((f, r[f].lower()))
    return ids


def reconstruct(rows, seed_id, mode="pid", dt=5.0):
    by_id = {r["record_id"]: r for r in rows}
    seed = by_id[seed_id]
    user = seed["user"]
    info = {r["record_id"]: (ts(r["utc_time"]), identifiers(r, mode)) for r in rows}
    included, frontier, links = {seed_id}, [seed_id], set()
    while frontier:
        cur = frontier.pop()
        t_cur, ids_cur = info[cur]
        for r in rows:
            rid = r["record_id"]
            if rid in included or (user and r["user"] and r["user"] != user):
                continue
            t, ids = info[rid]
            if abs((t - t_cur).total_seconds()) <= dt and ids & ids_cur:
                included.add(rid)
                frontier.append(rid)
                a, b = (cur, rid) if t_cur <= t else (rid, cur)
                links.add((a, b))
    return included, links


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events")
    ap.add_argument("--seed", required=True)
    ap.add_argument("--ids", choices=["pid", "guid"], default="pid")
    ap.add_argument("--dt", type=float, default=5.0)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    with open(a.events, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    included, links = reconstruct(rows, a.seed, a.ids, a.dt)
    name = "A (PIDs)" if a.ids == "pid" else "A' (GUIDs)"
    print(f"Method {name}: {len(included)} events, {len(links)} links from seed {a.seed}")
    if a.out:
        with open(a.out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["from_record", "to_record"])
            w.writerows(sorted(links))


if __name__ == "__main__":
    main()
