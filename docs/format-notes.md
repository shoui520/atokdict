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

Payload text scanning shows many plausible UTF-16BE runs in `DIC` and `DRT` payload areas. This
does not mean the whole file is UTF-16BE; it means lookup/content record bodies or embedded string
tables can use UTF-16BE even when the header title uses CP932.

## `DRW` and `DSZ` Companion Databases

`DRW` and `DSZ` files are SQLite databases obfuscated with a repeating 16-byte XOR key:

```text
06 68 5a 5e fa 4b 01 61 f6 93 85 b1 24 77 7a 82
```

After XOR decoding, every observed `DRW` and `DSZ` begins with the standard SQLite header
`SQLite format 3\0`.

Observed SQLite properties:

- Page size: 1024 bytes for every observed `DRW` and `DSZ`.
- Text encoding: SQLite encoding code `1` (`utf-8`).
- Schema format: `1`.

Observed `DRW` schema:

```sql
CREATE TABLE database_info (
  title TEXT NOT NULL,
  copyright TEXT,
  description TEXT,
  author TEXT,
  version INTEGER,
  revision INTEGER,
  classification TEXT,
  readonly_key TEXT,
  unique_id TEXT,
  uri TEXT,
  date INTEGER,
  libversion INTEGER,
  private_key TEXT
);

CREATE TABLE keyword_info (
  a_id INTEGER PRIMARY KEY,
  word TEXT NOT NULL
);

CREATE INDEX keyword_search_index on keyword_info(word);
```

Observed `DSZ` schema stores thesaurus/access data with `TABLE_HEADER`, `TABLE_CLASS`,
`TABLE_GROUP`, `TABLE_WORD`, and `TABLE_WORD_IHYOKI` plus indexes over class, group, reading,
surface form, label, and alternate surface-form fields.
