# atokdict

Python tooling and documentation for reverse engineering ATOK/JustSystems dictionary files.

This repository is source code and documentation only. Do not commit proprietary dictionary
payloads, installers, extracted data, generated exports, or private samples.

## Current Scope

- Parse common ATOK dictionary container headers.
- Inventory extracted dictionary folders and group sidecar files by basename.
- Produce redacted structural probes for `DIC`, `DAR`, `DRT`, `DRW`, `DSY`, and `DSZ` files.
- Document observed format facts as they are verified.

## CLI

```bash
python -m atokdict header /path/to/FILE.DIC
python -m atokdict sections /path/to/FILE.DRT
python -m atokdict drt-primary-index /path/to/FILE.DRT --limit 20
python -m atokdict drt-primary-blocks /path/to/FILE.DRT --limit 20
python -m atokdict drt-primary-segments /path/to/FILE.DRT --limit 20
python -m atokdict drt-root-index /path/to/FILE.DRT --limit 20
python -m atokdict drt-root-children /path/to/FILE.DRT --limit 20
python -m atokdict drt-keyword-ranges /path/to/FILE.DRT --limit 20
python -m atokdict drt-primary-keyword-ranges /path/to/FILE.DRT --limit 20
python -m atokdict dsy-map /path/to/FILE.DSY
python -m atokdict dsy-regions /path/to/FILE.DSY
python -m atokdict dsy-region1-index /path/to/FILE.DSY --limit 20
python -m atokdict dsy-region1-records /path/to/FILE.DSY --limit 20
python -m atokdict dsy-region3-prefix /path/to/FILE.DSY
python -m atokdict dsy-region3-sentinels /path/to/FILE.DSY --limit 20
python -m atokdict dsy-region3-first-run /path/to/FILE.DSY
python -m atokdict dsy-region3-first-run-links /path/to/FILE.DSY
python -m atokdict dsy-region3-gap4 /path/to/FILE.DSY
python -m atokdict dsy-region3-gap4-links /path/to/FILE.DSY
python -m atokdict inventory /path/to/dicts --json
python -m atokdict setup /path/to/SETUP.INI
python -m atokdict companion-header /path/to/FILE.DRW
python -m atokdict companion-schema /path/to/FILE.DSZ --counts --page-types
python -m atokdict scan-text-runs /path/to/FILE.DRT --limit 20
python -m atokdict scan-text-runs /path/to/FILE.DIC --encoding utf-16be --limit 20
```

The CLI defaults to structural output. It does not dump dictionary text unless explicitly
requested in future tooling.
