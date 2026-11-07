"""Chunk 1a.2/1a.3: profile downloaded OTRF host logs.

Writes data/catalog/otrf_profile.csv, one row per downloaded dataset:
event count, per-channel counts, Sysmon event-ID counts, hostnames, time span,
size, and malformed-line count. Joins technique/tactic info from the catalog.
Logs are untrusted data: only parsed with json.loads, never executed.
"""
import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "otrf"
CATALOG = ROOT / "data" / "catalog" / "otrf_datasets.csv"
OUT = ROOT / "data" / "catalog" / "otrf_profile.csv"


def fmt(counter):
    return ";".join(f"{k}:{v}" for k, v in sorted(counter.items(), key=lambda kv: str(kv[0])))


def main():
    with open(CATALOG, encoding="utf-8") as f:
        meta = {r["dataset_id"]: r for r in csv.DictReader(f)}

    rows = []
    for ds_dir in sorted(p for p in RAW.iterdir() if p.is_dir()):
        for path in sorted(ds_dir.glob("*.json")):
            channels, sysmon_ids, hosts = Counter(), Counter(), Counter()
            times, n, bad = [], 0, 0
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        bad += 1
                        continue
                    if not isinstance(d, dict):
                        bad += 1
                        continue
                    n += 1
                    ch = str(d.get("Channel", "?"))
                    channels[ch] += 1
                    hosts[str(d.get("Hostname", "?"))] += 1
                    if "sysmon" in ch.lower():
                        sysmon_ids[d.get("EventID")] += 1
                    t = d.get("TimeCreated") or d.get("EventTime")
                    if t:
                        times.append(str(t))
            m = meta.get(ds_dir.name, {})
            rows.append({
                "dataset_id": ds_dir.name,
                "title": m.get("title", ""),
                "techniques": m.get("techniques", ""),
                "tactics": m.get("tactics", ""),
                "file": str(path.relative_to(ROOT)),
                "size_mb": round(path.stat().st_size / 1e6, 2),
                "n_events": n,
                "n_malformed": bad,
                "n_sysmon": sum(sysmon_ids.values()),
                "channels": fmt(channels),
                "sysmon_event_ids": fmt(sysmon_ids),
                "hosts": fmt(hosts),
                "n_hosts": len(hosts),
                "time_start": min(times) if times else "",
                "time_end": max(times) if times else "",
            })

    if not rows:
        raise SystemExit(f"No logs found under {RAW}")
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    for r in rows:
        print(f"{r['dataset_id']}  {r['techniques']:<6} events={r['n_events']:<5} "
              f"sysmon={r['n_sysmon']:<5} hosts={r['n_hosts']}  {r['time_start']} -> {r['time_end']}")
    print(f"\nWrote {OUT}")


if __name__ == "__main__":
    main()
