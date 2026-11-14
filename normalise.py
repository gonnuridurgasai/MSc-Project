"""
normalise.py - convert exported Sysmon events into one clean table.

Input : an XML export (<Events><Event>...</Event>...</Events>), as written by
        run_feasibility_chain.ps1, or a .evtx file (needs: pip install python-evtx)
Output: a CSV with one row per event and the fields every method will use.

Usage:
    python normalise.py feasibility.xml events.csv
"""
import csv
import sys
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# Sysmon event IDs used in the project
EVENT_TYPES = {
    1: "process_create",
    3: "network_connect",
    5: "process_terminate",
    11: "file_create",
    13: "registry_set",
}

FIELDS = [
    "record_id", "event_id", "event_type", "utc_time", "user", "logon_id",
    "image", "command_line", "pid", "process_guid",
    "parent_image", "parent_pid", "parent_process_guid",
    "target_filename", "target_object", "dest_ip", "dest_port",
]

# Sysmon field name -> our column name
MAPPING = {
    "UtcTime": "utc_time", "User": "user", "LogonId": "logon_id",
    "Image": "image", "CommandLine": "command_line",
    "ProcessId": "pid", "ProcessGuid": "process_guid",
    "ParentImage": "parent_image", "ParentProcessId": "parent_pid",
    "ParentProcessGuid": "parent_process_guid",
    "TargetFilename": "target_filename", "TargetObject": "target_object",
    "DestinationIp": "dest_ip", "DestinationPort": "dest_port",
}


def parse_event(event_xml):
    """Turn one <Event> element into a dict of our columns (None if not Sysmon)."""
    system = event_xml.find("e:System", NS)
    provider = system.find("e:Provider", NS).get("Name", "")
    if "Sysmon" not in provider:
        return None
    event_id = int(system.find("e:EventID", NS).text)
    row = {f: "" for f in FIELDS}
    row["event_id"] = event_id
    row["event_type"] = EVENT_TYPES.get(event_id, f"other_{event_id}")
    row["record_id"] = system.find("e:EventRecordID", NS).text
    for data in event_xml.findall("e:EventData/e:Data", NS):
        col = MAPPING.get(data.get("Name"))
        if col:
            row[col] = (data.text or "").strip()
    return row


def read_events(path):
    if path.lower().endswith(".evtx"):
        from Evtx.Evtx import Evtx  # pip install python-evtx
        with Evtx(path) as log:
            for record in log.records():
                yield ET.fromstring(record.xml())
    else:
        with open(path, encoding="utf-8-sig") as f:
            root = ET.fromstring(f.read())
        yield from root.findall("e:Event", NS)


def normalise(in_path, out_path):
    rows = [r for r in (parse_event(e) for e in read_events(in_path)) if r]
    rows.sort(key=lambda r: (r["utc_time"], int(r["record_id"])))
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return rows


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python normalise.py <export.xml|export.evtx> <out.csv>")
    rows = normalise(sys.argv[1], sys.argv[2])
    counts = {}
    for r in rows:
        counts[r["event_type"]] = counts.get(r["event_type"], 0) + 1
    print(f"Wrote {len(rows)} Sysmon events to {sys.argv[2]}")
    for name, n in sorted(counts.items()):
        print(f"  {name:<18} {n}")
