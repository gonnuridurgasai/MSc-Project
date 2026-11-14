"""
method_b.py - Method B: provenance-based correlation.

Builds a directed graph from relationships Sysmon actually records:
    parent process -> child process   (event 1: ParentProcessGuid -> ProcessGuid)
    process -> file it created        (event 11)
    process -> registry value it set  (event 13)
    process -> network connection     (event 3)
    file -> process that later ran it (the file path appears in the new
                                       process's image or command line)
A process that started before the log began has no create event, but its
ProcessGuid is still recorded as a parent; it is kept as a virtual node.
Nodes are events (record IDs), so the output can be scored like Method A.

From the seed (alert) it traces BACKWARD along these edges to the origin of
the activity, then FORWARD from that origin to everything it caused, only
following edges whose times are consistent with cause and effect.
Shared identifiers or closeness in time are never treated as a link.

Usage:
    python method_b.py labelled.csv --seed <record_id> [--out links.csv]
"""
import argparse
import csv
from datetime import datetime

NULL_GUID = "{00000000-0000-0000-0000-000000000000}"


def ts(v):
    return datetime.strptime(v.strip(), "%Y-%m-%d %H:%M:%S.%f")


def build_graph(rows):
    """Return {node: set(successor nodes)} and its reverse.

    Nodes are event record IDs. A process whose creation happened before the
    log starts (so it has no process-create event here) is still a recorded
    entity: Sysmon names it by its ProcessGuid. Such a process becomes a
    "virtual" node "P:<guid>", so its children stay connected through it.
    """
    succ, pred = {}, {}
    for r in rows:
        succ[r["record_id"]] = set()
        pred[r["record_id"]] = set()
    created = {}  # process_guid -> record_id of its process-create event
    for r in rows:
        if r["event_type"] == "process_create":
            created[r["process_guid"]] = r["record_id"]

    def node(guid):
        if guid in created:
            return created[guid]
        v = "P:" + guid           # process seen only through its ProcessGuid
        succ.setdefault(v, set())
        pred.setdefault(v, set())
        return v

    def add(a, b):
        succ[a].add(b)
        pred[b].add(a)

    files = []  # (record_id, path, time)
    for r in rows:
        rid = r["record_id"]
        if r["event_type"] == "process_create":
            parent = r["parent_process_guid"]
            if parent and parent != NULL_GUID:
                add(node(parent), rid)
        elif r["event_type"] in ("file_create", "registry_set", "network_connect"):
            if r["process_guid"] and r["process_guid"] != NULL_GUID:
                add(node(r["process_guid"]), rid)
            if r["event_type"] == "file_create" and r["target_filename"]:
                files.append((rid, r["target_filename"].lower(), ts(r["utc_time"])))

    for fid, path, ft in files:  # file later executed by a new process
        for r in rows:
            if r["event_type"] == "process_create" and ts(r["utc_time"]) >= ft:
                if path in (r["image"] + " " + r["command_line"]).lower():
                    add(fid, r["record_id"])
    return succ, pred


def reconstruct(rows, seed_id):
    succ, pred = build_graph(rows)
    t = {r["record_id"]: ts(r["utc_time"]) for r in rows}
    for n in succ:                # a virtual process existed before all its effects
        if n not in t:
            t[n] = datetime.min

    # backward: walk to the origin(s), only through earlier causes
    origins, seen, stack = set(), {seed_id}, [seed_id]
    while stack:
        n = stack.pop()
        parents = [p for p in pred[n] if t[p] <= t[n]]
        if not parents:
            origins.add(n)
        for p in parents:
            if p not in seen:
                seen.add(p)
                stack.append(p)

    # forward: everything the origin(s) caused, only through later effects
    included, links, stack = set(origins), set(), list(origins)
    while stack:
        n = stack.pop()
        for s in succ[n]:
            if t[s] >= t[n]:
                links.add((n, s))
                if s not in included:
                    included.add(s)
                    stack.append(s)
    # report only event-to-event links (virtual process nodes are not events)
    events = {r["record_id"] for r in rows}
    return included & events, {(a, b) for a, b in links if a in events and b in events}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events")
    ap.add_argument("--seed", required=True)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    with open(a.events, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    included, links = reconstruct(rows, a.seed)
    print(f"Method B (provenance): {len(included)} events, {len(links)} links from seed {a.seed}")
    if a.out:
        with open(a.out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["from_record", "to_record"])
            w.writerows(sorted(links))


if __name__ == "__main__":
    main()
