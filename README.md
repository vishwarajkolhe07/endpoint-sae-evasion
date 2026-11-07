# Endpoint SAE Evasion

**Do Learned Attack Features Survive Evasion? Sparse Autoencoders on Endpoint Telemetry Transformers**

Train a small transformer on endpoint security event sequences, open it up with
sparse autoencoders (SAEs) to find learned attack-behavior features, and test
whether an adaptive attacker can evade both the detector and those features.

## Research questions

1. What attack behaviors does a telemetry transformer learn, and do they map to ATT&CK techniques?
2. Are those features behavioral (patterns of activity) or lexical (specific strings and binary names)?
3. Do SAE features recover techniques better than linear probes or rules?
4. When an adaptive attacker evades the detector, do the attack features still fire?

## Data sources

| Source | Role |
|---|---|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | Labeled, technique-tagged recordings |
| DARPA OpTC | Large-scale benign and attack telemetry (sanity check) |
| Own Sysmon lab | Controlled attacks and evasive variants |

Raw data is not stored in this repo. Each source has its own license and terms;
follow the links above. The scripts rebuild everything from public sources.

## Phases

1. Data and lab  *(in progress)*
2. Tokenizer
3. Pretraining
4. Detection
5. Sparse autoencoders
6. Feature analysis
7. Adaptive evasion
8. Defense (optional)

### Phase 1 status

- [x] 1a. OTRF Security-Datasets cataloged, 5 host-log datasets downloaded and profiled
- [ ] 1b. OpTC subset
- [ ] 1c. Windows VMs with Sysmon
- [ ] 1d. Atomic Red Team and Caldera
- [ ] 1e. Benign background activity
- [ ] 1f. Lab collection and leakage-safe splits

## Setup

```
pip install -r requirements.txt
```

## Reproducing chunk 1a

```
# 1. Sparse-clone only the OTRF metadata (the full repo includes every dataset zip)
git clone --depth 1 --filter=blob:none --sparse https://github.com/OTRF/Security-Datasets.git data/raw/Security-Datasets
git -C data/raw/Security-Datasets sparse-checkout set datasets/atomic/_metadata

# 2. Catalog all datasets by ATT&CK technique -> data/catalog/
python scripts/catalog_otrf.py

# 3. Download and extract the selected host-log zips -> data/raw/otrf/
python scripts/download_otrf.py

# 4. Profile the downloaded logs -> data/catalog/otrf_profile.csv
python -I scripts/profile_otrf.py
```

## Layout

```
scripts/        data collection and profiling scripts
data/catalog/   derived CSV catalogs (committed)
data/raw/       downloaded data (not committed)
```
