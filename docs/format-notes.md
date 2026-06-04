# ATOK Dictionary Format Notes

These notes record observed structure only. They should be updated when a field is
validated across more dictionaries.

## Container Families

Observed dictionary payload files use these extensions:

- `DIC`: main ATOK lookup dictionary sidecar.
- `DAR`: abbreviation or auxiliary lookup sidecar. Header magic is `DIC`, subtype is `DAR2`.
- `DRT`: rich dictionary text/content sidecar.
- `DRW`: binary sidecar associated with `DRT`, likely an index or resource table.
- `DSY`: access/search dictionary used by thesaurus and related dictionaries.
- `DSZ`: large companion payload for some `DSY` dictionaries.

## Common Header

The first 256 bytes are header-like for `DIC`, `DAR`, `DRT`, and `DSY`.

| Offset | Size | Observation |
| --- | ---: | --- |
| `0x00` | 4 | ASCII container magic plus NUL. Observed `DIC`, `DRT`, `DSY`. |
| `0x08` | 4 | ASCII subtype. Observed `ATOK` or `DAR2`. |
| `0x10` | 4 | Big-endian format/type code. Observed `0x000000a0` for many `DIC`, `0x00000f01` for many `DRT`, `0x00000e01` for `DSY`, `0x0000000b` for `DAR2`. |
| `0x14` | 1 | Variant byte. Meaning unknown. |
| `0x15` | 3 | BCD-looking build date: `YY MM DD`. |
| `0x1c` | 4 | Big-endian flag/count. Often `1` for `DIC`/`DAR`/`DRT`, `0` for `DSY`. |
| `0x3c` | 4 | BCD-looking constant date. Observed `1989-02-22`. |
| `0x40` | 64 | Title string, NUL padded. Observed CP932 for `DIC`/`DAR`/`DRT`; UTF-16BE for `DSY`. |

## Current Working Model

The installer metadata links sidecars by basename:

- `SetDic` installs `DIC` lookup sidecars.
- `SetAbbDic` installs `DAR` abbreviation/auxiliary sidecars.
- `SetDrtDic` installs `DRT` content sidecars.
- `SetAcsDic` installs `DSY` access/search sidecars.

The first implementation intentionally parses only the common header and structural text-run
locations. Entry extraction should wait until offset tables and record boundaries are better
understood.
