"""
dashboard.py - Attack Reconstruction Dashboard (first version).

Upload a lab run's sysmon.xml and ground_truth.json, click Analyse, and see:
  * what the run contains (attack, harness and background events)
  * the answer key (attack steps and true links)
  * each method's scores (Method A with PIDs, Method A' with GUIDs;
    Method B - provenance - will be added later)
  * a picture of each method's rebuilt attack (green correct, red wrong,
    dashed missed)
  * the full event table

Run on your laptop, from the lab folder:
    pip install streamlit
    streamlit run dashboard.py
"""
import csv
import os
import sys
import tempfile

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import json
import normalise
import label_ground_truth
import method_a
import method_b
import score
import draw_reconstruction

st.set_page_config(page_title="Attack Reconstruction Dashboard", layout="wide")
st.title("Attack Reconstruction Dashboard")
st.caption("Temporal/entity-based vs provenance-based correlation · MSc Cyber Security project")

with st.sidebar:
    st.header("1. Load a run")
    xml_file = st.file_uploader("Sysmon log (sysmon.xml)", type=["xml"])
    gt_file = st.file_uploader("Answer key (ground_truth.json)", type=["json"])
    st.header("2. Settings")
    dt = st.slider("Time window for Method A (seconds)", 1, 30, 5)
    run = st.button("Analyse", type="primary", disabled=not (xml_file and gt_file))

if not (xml_file and gt_file):
    st.info("Upload a run's **sysmon.xml** and **ground_truth.json** in the sidebar, then click **Analyse**.")
    st.stop()

if run or "result" in st.session_state:
    if run:
        work = tempfile.mkdtemp()
        p = lambda name: os.path.join(work, name)
        with open(p("sysmon.xml"), "wb") as f:
            f.write(xml_file.getvalue())
        gt = json.loads(gt_file.getvalue().decode("utf-8-sig"))

        rows = normalise.normalise(p("sysmon.xml"), p("events.csv"))
        with open(p("events.csv"), encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        gt_links = label_ground_truth.label(rows, gt)
        gt_set = {(a, b) for a, b, _ in gt_links}

        seed = next((r["record_id"] for r in rows if r["event_type"] == "registry_set"
                     and "\\currentversion\\run" in r["target_object"].lower()), None)
        if seed is None:
            seed = next(r["record_id"] for r in rows if r["label"] == "attack")

        with open(p("labelled.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        with open(p("gt_links.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["from_record", "to_record"])
            w.writerows(sorted(gt_set))

        results, link_files = {}, []
        for mode, name, fname in (("pid", "Method A (PIDs)", "A_pid.csv"),
                                  ("guid", "Method A' (GUIDs)", "A_guid.csv")):
            _, links = method_a.reconstruct(rows, seed, mode, float(dt))
            with open(p(fname), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["from_record", "to_record"])
                w.writerows(sorted(links))
            results[name] = score.score(links, gt_set, rows)
            link_files += [p(fname), name]

        _, links = method_b.reconstruct(rows, seed)
        with open(p("B_prov.csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["from_record", "to_record"])
            w.writerows(sorted(links))
        results["Method B (provenance)"] = score.score(links, gt_set, rows)
        link_files += [p("B_prov.csv"), "Method B (provenance)"]

        draw_reconstruction.main(p("labelled.csv"), p("gt_links.csv"), p("picture.png"), *link_files)
        st.session_state["result"] = dict(gt=gt, rows=rows, gt_links=gt_links, seed=seed,
                                          results=results, picture=p("picture.png"))

    R = st.session_state["result"]
    rows, gt = R["rows"], R["gt"]

    # --- Run overview -------------------------------------------------------
    st.subheader(f"Run: {gt.get('run_id', '')}")
    counts = pd.Series([r["label"] for r in rows]).value_counts()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total events", len(rows))
    c2.metric("Attack events", int(counts.get("attack", 0)))
    c3.metric("Background events", int(counts.get("benign", 0)))
    c4.metric("Framework (harness) events", int(counts.get("harness", 0)))
    st.caption(f"Scenario {gt.get('scenario')} · activity level {gt.get('level')} · seed {gt.get('seed')} · "
               f"alert (starting event) = record {R['seed']}")

    # --- Answer key --------------------------------------------------------
    st.subheader("Answer key")
    steps = pd.DataFrame(gt["steps"])[["step", "tactic", "technique", "test_name"]]
    st.dataframe(steps, hide_index=True, use_container_width=True)
    with st.expander(f"True links ({len(R['gt_links'])})"):
        st.dataframe(pd.DataFrame(R["gt_links"], columns=["from event", "to event", "relation"]),
                     hide_index=True, use_container_width=True)

    # --- Scores ------------------------------------------------------------
    st.subheader("Scores")
    table = pd.DataFrame([{"Method": name, "Correct links": s["tp"], "Wrong links": s["fp"],
                           "Missed links": s["fn"], "Precision": round(s["precision"], 2),
                           "Recall": round(s["recall"], 2), "F1": round(s["f1"], 2)}
                          for name, s in R["results"].items()])
    st.dataframe(table, hide_index=True, use_container_width=True)

    # --- Picture -----------------------------------------------------------
    st.subheader("Rebuilt attack")
    st.image(R["picture"], use_container_width=True)

    # --- Events ------------------------------------------------------------
    st.subheader("All events")
    show = st.multiselect("Show labels", ["attack", "benign", "harness"], default=["attack", "benign", "harness"])
    df = pd.DataFrame(rows)
    df["program"] = df["image"].str.split("\\").str[-1]
    cols = ["record_id", "label", "step", "event_type", "utc_time", "program", "pid", "parent_pid",
            "command_line", "target_filename", "target_object"]
    st.dataframe(df[df["label"].isin(show)][cols], hide_index=True, use_container_width=True)
