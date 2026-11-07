"""Chunk 1a: catalog OTRF Security-Datasets by ATT&CK technique.

Reads the YAML metadata files shipped in the repo (no large downloads needed)
and writes:
  data/catalog/otrf_catalog.csv      one row per (dataset, technique) pair
  data/catalog/otrf_datasets.csv     one row per dataset, with file links/sizes
  data/catalog/otrf_technique_summary.csv   datasets per technique
  data/catalog/otrf_candidates.csv   shortlist for download (1a.1)

Usage:  python scripts/catalog_otrf.py [--repo PATH] [--out PATH]
Treats the cloned repo as untrusted data: YAML is read with safe_load only.
"""
import argparse
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = ROOT / "data" / "raw" / "Security-Datasets"
DEFAULT_OUT = ROOT / "data" / "catalog"

# Techniques of interest for Phase 7 (evasion) -- used only for ranking candidates.
PRIORITY_TACTICS = {
    "TA0002",  # execution
    "TA0003",  # persistence
    "TA0004",  # privilege escalation
    "TA0005",  # defense evasion
    "TA0006",  # credential access
    "TA0008",  # lateral movement
}


def load_metadata(repo: Path):
    meta_dir = repo / "datasets" / "atomic" / "_metadata"
    if not meta_dir.is_dir():
        raise SystemExit(f"Metadata folder not found: {meta_dir}")
    for path in sorted(meta_dir.glob("*.yaml")):
        try:
            with open(path, encoding="utf-8") as f:
                doc = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            print(f"[warn] skipping {path.name}: {exc}")
            continue
        if isinstance(doc, dict):
            yield path, doc


def as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    tech_rows, ds_rows = [], []
    for path, doc in load_metadata(args.repo):
        ds_id = doc.get("id") or path.stem
        files = [f for f in as_list(doc.get("files")) if isinstance(f, dict)]
        links = [f.get("link", "") for f in files]
        file_types = sorted({str(f.get("type", "")) for f in files})
        n_host = sum(1 for f in files if str(f.get("type", "")).lower() == "host")
        platforms = ";".join(str(p) for p in as_list(doc.get("platform")))
        mappings = [m for m in as_list(doc.get("attack_mappings")) if isinstance(m, dict)]

        techniques = sorted({str(m.get("technique", "")) for m in mappings if m.get("technique")})
        tactics = sorted({t for m in mappings for t in as_list(m.get("tactics"))})

        ds_rows.append({
            "dataset_id": ds_id,
            "title": doc.get("title", ""),
            "platform": platforms,
            "type": doc.get("type", ""),
            "created": doc.get("creation_date", ""),
            "n_files": len(files),
            "n_host_files": n_host,
            "file_types": ";".join(file_types),
            "download_links": " | ".join(links),
            "techniques": ";".join(techniques),
            "tactics": ";".join(tactics),
            "n_techniques": len(techniques),
            "metadata_file": path.name,
        })

        for m in mappings:
            tech_rows.append({
                "dataset_id": ds_id,
                "title": doc.get("title", ""),
                "technique": m.get("technique", ""),
                "sub_technique": m.get("sub-technique", ""),
                "tactics": ";".join(as_list(m.get("tactics"))),
                "platform": platforms,
                "n_files": len(files),
            })

    catalog = pd.DataFrame(tech_rows)
    datasets = pd.DataFrame(ds_rows)
    if catalog.empty:
        raise SystemExit("No attack_mappings found; check the repo layout.")

    summary = (
        catalog.groupby("technique")
        .agg(n_datasets=("dataset_id", "nunique"),
             sub_techniques=("sub_technique", lambda s: ";".join(sorted({x for x in s if x}))),
             tactics=("tactics", lambda s: ";".join(sorted({t for x in s for t in x.split(";") if t}))),
             datasets=("dataset_id", lambda s: ";".join(sorted(set(s)))))
        .reset_index()
        .sort_values("n_datasets", ascending=False)
    )

    # Candidate shortlist: Windows, has host-log files, single/few techniques
    # (cleaner labels), tactic in the priority set. Review by hand before downloading.
    cand = datasets[(datasets["n_host_files"] > 0) &
                    (datasets["platform"].astype(str).str.lower().str.contains("windows"))].copy()
    cand["priority_hits"] = cand["tactics"].apply(
        lambda s: len(PRIORITY_TACTICS & set(s.split(";"))) if s else 0)
    cand = cand.sort_values(["n_techniques", "priority_hits"], ascending=[True, False])

    catalog.to_csv(args.out / "otrf_catalog.csv", index=False)
    datasets.to_csv(args.out / "otrf_datasets.csv", index=False)
    summary.to_csv(args.out / "otrf_technique_summary.csv", index=False)
    cand.to_csv(args.out / "otrf_candidates.csv", index=False)

    print(f"datasets: {len(datasets)}  |  with files: {(datasets.n_files > 0).sum()}")
    print(f"distinct techniques: {summary.shape[0]}")
    print(f"candidates (Windows, downloadable): {len(cand)}")
    print("\nTop techniques by dataset count:")
    print(summary.head(15)[["technique", "n_datasets", "tactics"]].to_string(index=False))
    print(f"\nWrote CSVs to {args.out}")


if __name__ == "__main__":
    main()
