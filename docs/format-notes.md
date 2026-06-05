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

## `DSY` Metadata And Region Map

Observed `DSY` files do not use the `DIC`/`DAR`/`DRT` descriptor area, but four observed files do
share a fixed metadata/map area beginning at `0x300`.

Observed `0x300` metadata words:

| Offset | Size | Observation |
| --- | ---: | --- |
| `0x300` | 4 | Constant `0x004000ff` in observed files. |
| `0x304` | 4 | Constant `1` in observed files. |
| `0x308` | 4 | Constant `0x00ffffff` in observed files. |
| `0x30c` | 4 | Region-1 table record count in observed files. |
| `0x310` | 4 | Constant `0x00200200` in observed files. |
| `0x314` | 4 | High 16 bits are `0xffff`; low 16 bits are count-like. |
| `0x318` | 4 | Constant `0x00080000` in observed files. |
| `0x31c` | 4 | Constant `0x00010000` in observed files. |
| `0x320..0x328` | 12 | Zero-filled in observed files. |
| `0x32c` | 4 | Constant `4` in observed files. |

The region table at `0x330..0x360` consists of 8-byte big-endian `(offset, byte_length)` pairs.
Four non-zero regions are observed. They are contiguous, start at `0x360`, and end at EOF. The
first region is always `0x360 + 0x200`. The `dsy-map` command reports these fields and region
descriptors without dumping region bytes.

Region 0 is always 512 bytes and, when interpreted as 256 big-endian 16-bit words, is a
permutation of values `1..256`. Region 3 prefixes commonly contain the same marker words observed
in DRT child/primary diagnostics: `0xffff`, `0xfffe`, and `0xfffd`. The `dsy-regions` command
reports bounded region diagnostics: prefix hashes, byte ratios, marker positions/counts, 16-bit
word counts, and whether region 0 is the observed `1..256` permutation.

Region 1 begins with an 8-byte-record boundary table. Metadata field `0x30c` is the observed
table record count, so the table byte length is `field_0x30c * 8`. The first table record is a
header-like pair `(table_byte_length, 0)`. Subsequent records are
`(payload_byte_length, cumulative_payload_end)` pairs that partition the covered region-1 payload
immediately after the table. All observed DSY files also have a small unassigned region-1 trailer
after the covered payload. The `dsy-region1-index` command reports this structure without dumping
payload bytes.

The `dsy-region1-records` command reports bounded diagnostics for those indexed payload records
and the trailer: prefix hashes, byte ratios, marker positions/counts, and candidate absolute or
relative offset counts by DSY region. It does not dump payload bytes or decoded text.

Region 3 begins with a 16-bit even value that is a plausible prefix byte length in every observed
DSY file. The prefix contains the recurring marker words and many high `0xffxx` sentinel-like
words; a bounded scan immediately after the prefix has not shown those marker words. The
`dsy-region3-prefix` command reports this split candidate with hashes, marker counts, 16-bit word
counts, and candidate offset-reference counts.

High `0xffxx` words in the region-3 prefix form descending sentinel runs. The
`dsy-region3-sentinels` command reports those run boundaries and lengths without dumping prefix
bytes. Full DSY files have a large first descending run starting at word index 8; the small
`THESAURUS.DSY` stub has only a single high word in the prefix.

The `dsy-region3-first-run` command reports aggregate shape for that first run: word span, gap
histogram, sentinel count, and non-sentinel filler-word statistics. It does not dump the local
word sequence.

The `dsy-region3-gap4` command summarizes the dominant gap-4 chunks inside the first sentinel run.
It reports slot-level aggregate statistics for the three non-sentinel words between adjacent
descending sentinels, without emitting the word triples.

## `DRT` Primary Index Table

Every observed `DRT` has a descriptor-`0x390` primary index table. Its length is a multiple of 20
bytes. Each record points into descriptor `0x3a8`, and all observed pointers are monotonic.

Observed 20-byte record:

| Relative offset | Size | Observation |
| --- | ---: | --- |
| `+0x00` | 4 | Separator key bytes. Encoding varies; observed ASCII, UTF-16BE-like, and binary-looking values. |
| `+0x04` | 4 | Big-endian absolute offset into descriptor `0x3a8`. |
| `+0x08` | 4 | Byte length of primary block segment 1. |
| `+0x0c` | 4 | Byte length of primary block segment 2. |
| `+0x10` | 4 | Byte length of primary block segment 0. |

Adjacent primary-index offsets partition descriptor `0x3a8`; the final primary block ends at
descriptor `0x3a8` EOF. The `drt-primary-index` command reports redacted separator-key hashes,
encoding guesses, field lengths, derived segment offsets, and block sizes. Across all observed
records, `field_0x10 + field_0x08 + field_0x0c == primary_block_length`. Segment order in the
payload block is `0x10`, then `0x08`, then `0x0c`; segment contents are not assigned yet.

The three primary block segments have stable unit alignment across all 1064 observed records:

| Segment | Unit size | Observation |
| --- | ---: | --- |
| 0 | 64 bytes | Large stream, likely node/control blocks. |
| 1 | 4 bytes | Count is repeated in segment-0 header word 0 plus one. |
| 2 | 8 bytes | Count is repeated in segment-0 header word 1. |

The first 16 bytes of segment 0 behave like an 8-word big-endian 16-bit block header. For every
observed primary record:

- header word 0 plus one equals `segment_1_byte_length / 4`;
- header word 1 equals `segment_2_byte_length / 8`;
- header word 3 is zero;
- header words 2, 4, 5, and 7 are valid segment-1 unit indexes;
- header word 6 is either a valid segment-1 unit index or `0xffff`.

The `drt-primary-blocks` command reports primary block unit counts, these segment-0 header words,
whether the header count fields match the derived segment sizes, and whether the apparent
segment-1 reference words are in range. The roles of these segment-1 references are still
unassigned.

The `drt-primary-segments` command reports bounded-prefix diagnostics for those derived segments:
offsets, lengths, prefix hashes, NUL ratio, printable-ASCII ratio, unique byte count, marker counts,
first marker offsets, and possible absolute-offset candidate counts. It does not emit raw segment
bytes or decoded text.

Across 1064 primary records in 38 observed `DRT` files, segment 0 is much larger and more
index-like than segments 1 and 2. In 4096-byte bounded-prefix scans, segment 0 averaged many more
possible absolute-offset candidates and almost always contained at least one of the existing
16-bit marker words (`0xffff`, `0xfffe`, `0xfffd`). Segments 1 and 2 had higher printable-ASCII
ratios, very low NUL ratios, and few marker hits. This suggests segment 0 is likely a node/index
stream, while segments 1 and 2 are separate auxiliary or blob-like streams. The roles are still
unassigned.

When a matching `DRW` companion exists, the 4-byte primary separator key can also be tested against
`keyword_info.word` sort order. In English dictionaries such as `LDOCE`, `LEJBD`, and `GENIUSEJ`,
the decodable primary separator ranks are monotonic. A binary-looking final primary key then acts
like a terminal separator, giving one keyword-rank range per primary block:

- primary block 0 covers keyword ranks `[0, separator_0_rank)`;
- primary block N covers `[separator_(N-1)_rank, separator_N_rank)`;
- the terminal binary separator covers `[last_separator_rank, keyword_count)`.

The `drt-primary-keyword-ranges` command reports this linkage with separator hashes, encoding
guesses, lower-bound ranks, exact/prefix match counts, and derived partition sizes. It does not
emit raw separator keys or keyword text. Japanese primary separator ranks are not generally
monotonic under the current naive decoded-key model, so the command reports `null` partitions when
the rank sequence is not monotonic.

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
