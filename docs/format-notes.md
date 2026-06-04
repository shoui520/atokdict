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

## Section Descriptors

`DIC`, `DAR`, and `DRT` containers have a descriptor area in the extended header near
`0x380..0x400`. Entries are big-endian 32-bit `(offset, byte_length)` pairs. Zero pairs are unused.
Observed descriptors are structural maps into later file regions; semantics are not fully assigned
yet.

For `DRT`, descriptors generally cover several regions and the final non-zero descriptor often
ends exactly at EOF. Small high-value examples:

- `TSK_YOJIJUKUGO.DRT`: final descriptor `0x2d0e58 + 0x4da92 = EOF`.
- `MK_KOTOWAZA.DRT`: final descriptor `0x4eecb0 + 0xb3c1e = EOF`.
- `KOUJIEN.DRT`: final descriptor `0x147c83b2 + 0x1398634 = EOF`.

For `DIC` and `DAR`, observed descriptors include fixed early regions such as
`0x300+0x100`, `0x400+0x300`, and `0x700+0x200`, plus later small region descriptors in some
files. `DSY` files do not appear to use this descriptor layout.

## `DRT` Primary Index Table

Every observed `DRT` has a descriptor-`0x390` primary index table. Its length is a multiple of 20
bytes. Each record points into descriptor `0x3a8`, and all observed pointers are monotonic.

Observed 20-byte record:

| Relative offset | Size | Observation |
| --- | ---: | --- |
| `+0x00` | 4 | Separator key bytes. Encoding varies; observed ASCII, UTF-16BE-like, and binary-looking values. |
| `+0x04` | 4 | Big-endian absolute offset into descriptor `0x3a8`. |
| `+0x08` | 4 | Unknown numeric field. |
| `+0x0c` | 4 | Unknown numeric field. |
| `+0x10` | 4 | Unknown numeric field. |

Adjacent primary-index offsets partition descriptor `0x3a8`; the final primary block ends at
descriptor `0x3a8` EOF. The `drt-primary-index` command reports redacted separator-key hashes,
encoding guesses, unknown numeric fields, offsets, and block sizes.

## `DRT` Final-Section Root Index

Many Japanese `DRT` files with seven parsed section descriptors use the final section as a
root-index area. This is not universal; English and some auxiliary DRT files use a different final
section layout.

Observed root-index layout:

| Relative offset | Size | Observation |
| --- | ---: | --- |
| `0x00` | 4 | Big-endian root entry count. |
| `0x04` | 10 | Zero-filled in observed root-index files; meaning unknown. |
| `0x0e` | variable | Root records with a 16-byte prefix and UTF-16BE separator key. |

Observed root record fixed prefix:

| Relative offset | Size | Observation |
| --- | ---: | --- |
| `+0x00` | 4 | Big-endian absolute offset into the same final section. |
| `+0x04` | 2 | Flag-like value. Observed `0` and `1`; semantics unknown. |
| `+0x06` | 2 | Tag/value field. Semantics unknown. |
| `+0x08` | 4 | Numeric field. Semantics unknown. |
| `+0x0c` | 4 | Numeric field. Semantics unknown. |
| `+0x10` | variable | UTF-16BE separator key bytes. |

The root record area ends at the smallest absolute offset referenced by the root records. The
current parser uses that invariant to find the final root key boundary and redacts keys by default
in CLI output.

The root record offsets partition the rest of the final section into child blocks. Child block
length is the difference between adjacent root offsets, with the final child ending at the final
section EOF. These child blocks are not parsed yet, but bounded-prefix diagnostics show repeatable
16-bit markers:

- `0xffff`
- `0xfffe`
- `0xfffd`

The `drt-root-children` command reports child block offsets, lengths, root numeric fields, marker
positions/counts in a bounded prefix, and hashes. It does not emit raw child bytes or decoded child
payload.

When a matching `DRW` companion exists, non-empty root separator keys are monotonic in
`keyword_info.word` sort order. The final root entry generally has an empty separator key and closes
the final keyword range. This gives a root-level keyword partition model:

- child block 0 covers keyword ranks `[0, separator_0_rank)`;
- child block N covers `[separator_(N-1)_rank, separator_N_rank)`;
- the empty final separator covers `[last_separator_rank, keyword_count)`.

Exact separator-key matches in `keyword_info` are sparse, so separators should be treated as split
boundaries rather than entry headwords. The `drt-keyword-ranges` command reports these ranges using
keyword ranks, lower-bound `a_id` values, exact-match counts, and hashes.

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
