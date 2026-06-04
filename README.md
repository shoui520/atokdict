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
python -m atokdict inventory /path/to/dicts --json
python -m atokdict setup /path/to/SETUP.INI
python -m atokdict scan-text-runs /path/to/FILE.DRT --limit 20
python -m atokdict scan-text-runs /path/to/FILE.DIC --encoding utf-16be --limit 20
```

The CLI defaults to structural output. It does not dump dictionary text unless explicitly
requested in future tooling.
