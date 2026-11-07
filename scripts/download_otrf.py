"""Chunk 1a.1: download selected OTRF host-log zips and extract them safely.

Each dataset goes into its own folder: data/raw/otrf/<dataset_id>/
Only host logs (URLs containing /host/) are fetched; network pcaps are skipped.
Downloaded archives are untrusted: extraction rejects paths that escape the
target folder (zip-slip), and nothing is executed.

Usage:
  python scripts/download_otrf.py                  # default selection
  python scripts/download_otrf.py SDWIN-... SDWIN-...   # explicit IDs
  python scripts/download_otrf.py --max-mb 500     # raise size guard
"""
import argparse
import csv
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "data" / "catalog" / "otrf_datasets.csv"
OUT_DIR = ROOT / "data" / "raw" / "otrf"
SELECTED_CSV = ROOT / "data" / "catalog" / "otrf_selected.csv"

DEFAULT_SELECTION = [
    "SDWIN-201018195009",  # T1003 Lsass dump via Comsvcs.dll
    "SDWIN-190518210652",  # T1021 Empire Invoke PsExec
    "SDWIN-201023031210",  # T1055 PurpleSharp PE injection CreateRemoteThread
    "SDWIN-201219070027",  # T1053 Remote scheduled task creation
    "SDWIN-200806035621",  # T1047 Covenant SharpWMI exec
]


def remote_size(url: str) -> int:
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers.get("Content-Length", 0))


def safe_extract(zip_path: Path, dest: Path) -> list[Path]:
    dest_resolved = dest.resolve()
    extracted = []
    with zipfile.ZipFile(zip_path) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if dest_resolved != target and dest_resolved not in target.parents:
                raise RuntimeError(f"Unsafe path in archive: {info.filename}")
        z.extractall(dest)
        extracted = [dest / i.filename for i in z.infolist() if not i.is_dir()]
    return extracted


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*", default=DEFAULT_SELECTION)
    ap.add_argument("--max-mb", type=int, default=300, help="skip zips larger than this")
    args = ap.parse_args()

    with open(CATALOG, encoding="utf-8") as f:
        rows = {r["dataset_id"]: r for r in csv.DictReader(f)}

    selected_rows = []
    for ds_id in args.ids:
        row = rows.get(ds_id)
        if not row:
            print(f"[skip] {ds_id}: not in catalog")
            continue
        host_links = [u.strip() for u in row["download_links"].split("|") if "/host/" in u]
        if not host_links:
            print(f"[skip] {ds_id}: no host link")
            continue

        ds_dir = OUT_DIR / ds_id
        ds_dir.mkdir(parents=True, exist_ok=True)
        for url in host_links:
            zip_path = ds_dir / Path(url).name
            size = remote_size(url)
            print(f"{ds_id}: {Path(url).name} ({size / 1e6:.1f} MB)")
            if size > args.max_mb * 1e6:
                print(f"  [skip] larger than {args.max_mb} MB; rerun with --max-mb")
                continue
            if not zip_path.exists():
                urllib.request.urlretrieve(url, zip_path)
            files = safe_extract(zip_path, ds_dir)
            total = sum(p.stat().st_size for p in files if p.exists())
            print(f"  extracted {len(files)} file(s), {total / 1e6:.1f} MB")
            selected_rows.append({
                "dataset_id": ds_id, "title": row["title"],
                "techniques": row["techniques"], "tactics": row["tactics"],
                "zip": str(zip_path.relative_to(ROOT)),
                "extracted_files": ";".join(str(p.relative_to(ROOT)) for p in files),
                "extracted_mb": round(total / 1e6, 1),
            })

    if selected_rows:
        with open(SELECTED_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(selected_rows[0].keys()))
            w.writeheader()
            w.writerows(selected_rows)
        print(f"\nWrote {SELECTED_CSV}")


if __name__ == "__main__":
    main()
