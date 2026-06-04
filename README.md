# Caesar Cipher & Deck Stacking in NY Voter ID Numbers

A Python emulation of the "Spiral" algorithm described in:

> **Paquette, A. (2023).** *The Caesar Cipher and Stacking the Deck in New York State Voter Rolls.*  
> New York Citizens' Audit (NYCA). Published via ResearchGate, May 2023.  
> [https://www.researchgate.net/publication/370835885](https://www.researchgate.net/publication/370835885)

---

## Background

New York State voter rolls assign each registered voter two identification numbers:

- **SBOEID** — State Board of Elections ID (`NY000000000012345678`, analyzed as an 8-digit Short ID)
- **CID** — County Voter Registration Number (format varies by county: 5–9 digits, sometimes alphanumeric)

Paquette's research found that these two numbers are not assigned randomly or sequentially. Instead, they are linked by a hidden algorithm — dubbed **"The Spiral"** — present in 58 of New York's 62 counties. The algorithm:

1. Divides county CID numbers into logical **strips** (by digit length or leading character)
2. Applies a **Caesar cipher** transformation to each strip (cut near the start, swap the segments)
3. **Interlaces** the strips together like a stacked deck of cards, using repunit-based spacing
4. Assigns **consecutive SBOEID numbers** to the resulting reordered CID sequence

The result is that voter ID numbers carry hidden structural information — invisible to normal users, but readable to anyone who knows the algorithm key.

---

## The Core Claim

The paper argues the algorithm serves one purpose: **covert tagging of fraudulent voter registrations**.

Rather than marking fraudulent records with an obvious flag, the algorithm encodes a record's status in the *relationship* between its SBOEID and CID numbers — specifically, where that pairing lands in the stacked deck. This is a form of [steganography](https://en.wikipedia.org/wiki/Steganography): hiding information in plain sight.

From the paper (p. 17–18):

> *"Instead of altering numbers, it assigns certain SBOEID numbers to certain CID numbers. This allows the original ID numbers to remain unaltered at the same time they are tagged by associating them with each other."*

A keyholder with knowledge of the algorithm can:
- Extract only fraudulent records instantly from the full voter roll
- Mark those records as having voted after fraudulent ballots are cast
- Leave the totals balanced, with no anomaly visible to a standard audit

---

## Key Concepts

### Repunits
The algorithm's spacing constants are **repunits** — numbers composed entirely of repeated `1`s:

| Repunit | Value |
|---------|-------|
| `11` | 11 |
| `111` | 111 |
| `1,111` | 1,111 |
| `11,111` | 11,111 |
| `111,111` | 111,111 |

Related values (quarter and three-quarter repunits) mark strip boundaries:
- **25% repunit**: e.g., `278` (≈ 277.75, or 25% of 1,111)
- **75% repunit**: e.g., `833` (≈ 833.25, or 75% of 1,111)

When records are sorted by CID, the SBOEID gaps cluster around `1,111` and `1,112`. When sorted by SBOEID, the strip pattern appears in the CID column.

### The Three Partitions

The full SBOEID number space (8-digit Short IDs: `00000000` – `99999999`) is divided into three partitions:

| Partition | Range | Count | Notes |
|-----------|-------|-------|-------|
| Out of Range Low (OOR-L) | `0` – `8,502,558` | 2,436 | Mixed counties, small |
| **In Range (IR)** | `8,502,559` – `40,481,161` | **11,822,181** | The Spiral lives here (56.93% of all records) |
| Out of Range High (OOR-H) | `40,481,162` – `99,999,999` | 8,940,618 | "Tartan" algorithm (unsolved) |

The IR partition is subdivided into 62 county-specific ranges — but **not** in alphabetical order by county code, adding an additional layer of obfuscation.

### The Algorithmic ID (AID)

Every IR record's position in the stacked deck can be encoded as a hidden **10-digit Algorithmic ID**:
- Each pair of digits represents a position within one of the five strips (01–99)
- Example from the paper: CID #23,765 → AID `0110060311`
- This AID does not appear anywhere in the voter roll database — it exists only for keyholders

### The OOR "Slab" Problem

In the OOR-High partition, a scatter plot of SBOEID vs. CID reveals two formation types:
- **Columns** (vertical orientation) → Active records
- **Slabs** (horizontal orientation) → Purged records

No active records appear in slab regions. Of Nassau County's 176,090 slab records, **>99.9% are purged** — and 27.38% are identified as clones (duplicate SBOEID numbers attached to the same voter, which is illegal under NY Election Law §6217.6).

The paper asks: if slab records were created purged, who knew they were ineligible at the moment of creation?

---

## Files

| File | Description |
|------|-------------|
| `spiral_algorithm.py` | Core Spiral algorithm: strip creation, Caesar cipher, deck stacking, SBOEID assignment |
| `spiral_tagging.py` | Covert tagging mechanism: legitimate vs. fraudulent record injection, keyholder extraction, ballot reconciliation demo |

---

## Usage

No dependencies beyond the Python standard library.

```bash
python spiral_algorithm.py
python spiral_tagging.py
```

### `spiral_algorithm.py` — what it demonstrates

- Divides simulated CID numbers into strips by digit length
- Applies the Caesar cipher cut-and-swap to each strip
- Interlaces strips using repunit spacing (1111, 111, 11, 1...)
- Assigns consecutive SBOEIDs to the reordered sequence
- Shows the repunit gap pattern visible in a CID sort
- Confirms that only ~5% of positions match original order (the scramble is real)

### `spiral_tagging.py` — what it demonstrates

- Injects 60 fraudulent records into a 500-record legitimate voter roll
- Shows the "without key" view: all records look identical
- Shows the "with key" view: fraudulent records are identifiable by deck position
- Runs an accuracy report comparing algorithm-based extraction to random guessing
- Simulates ballot reconciliation: fake votes marked, totals balance, audit sees nothing

---

## Allegany County Example (from the paper, Table 6)

The paper gives a concrete worked example for Allegany County, Strip 3:

| Strip | First CID (Start Seg 2) | End continuous | Start alternating | Interval | Repeat | End Seg 2 | Start Seg 1 | Last CID |
|-------|------------------------|----------------|-------------------|----------|--------|-----------|-------------|----------|
| 01 | 1 | | | | | | | 9 |
| 02 | 17 | | | | | 99 | 10 | 16 |
| **03** | **146** | **911** | **103/913** | **10** | **7** | **999** | **115** | **145** |
| 04 | 1,340 | 9,516 | 1,001/9,518 | 10 | 30 | 9,997 | 1,047 | 1,339 |
| 05 | 13,214 | | | | | 91,126 | 10,001 | 13,213 |

Strip 3 (CIDs 103–999) was cut between 145 and 146. Numbers 103–145 became Segment 1, moved to the end of Segment 2. The first seven numbers of Segment 1 (103–114, with gaps) were then interlaced every 10 numbers into the last 70 numbers approaching 999.

---

## Yates County Strip Ranges (from the paper, Figure 5)

| Strip | Strip Min SBOEID | Distance to Min | Gap between SBOEIDs in strip | Distance to Max | Strip Max | Strip Range |
|-------|-----------------|-----------------|------------------------------|-----------------|-----------|-------------|
| 1 | 21,704,366 | 0 | 0 | 14,455 | 21,704,366 | 14,455 |
| 2 | 21,707,144 | 2,778 | 1,111 | 5,833 | 21,712,988 | 5,844 |
| 3 | 21,705,199 | 833 | 111 | 278 | 21,718,543 | 13,344 |
| 4 | 21,704,449 | 83 | 11 | 28 | 21,718,793 | 14,344 |
| 5 | 21,704,374 | 8 | 11 | 3 | 21,718,818 | 14,444 |
| 6 | 21,704,367 | 1 | 1 | 0 | 21,718,821 | 14,454 |

Strip ranges drop by 10, then 100, then 1,000 — allowing all strips to nest within each other without overlap.

---

## Important Caveats

This repository emulates the algorithm as described in the paper for **educational and analytical purposes only**. Several important caveats apply:

1. **Not peer-reviewed.** The paper was published on ResearchGate, a document-sharing platform, not a peer-reviewed journal. It has not undergone independent academic review.

2. **Source conflict of interest.** NYCA began its investigation with the stated premise that fraud occurred. This is a meaningful analytical bias.

3. **No independent official confirmation.** New York election officials, federal agencies, and courts have not validated these findings. Repeated legal challenges to New York's 2020 election results were rejected.

4. **Alternative explanations exist.** Complex-looking patterns in large legacy databases commonly arise from batch processing, software migration artifacts, load-balancing schemes, or other mundane engineering decisions. The paper does not fully rule these out.

5. **The code here is a reconstruction.** NYCA never published source code. This implementation is built from the paper's written description and may not perfectly match the actual algorithm.

The question the paper asks — *"why is it there?"* — remains unanswered by any official investigation.

---

## References

- Paquette, A. (2023). *The Caesar Cipher and Stacking the Deck in New York State Voter Rolls.* New York Citizens' Audit. [ResearchGate](https://www.researchgate.net/publication/370835885)
- Bolton, R.J. & Hand, D.J. (2002). Statistical fraud detection: A review. *Statistical Science*, 17, 235–49.
- Francis, R.L. (1988). Mathematical haystacks: Another look at repunit numbers. *The College Mathematics Journal*, 19, 240–6.
- Luciano, D. & Pritchett, G. (1987). Cryptology: From Caesar ciphers to public-key cryptosystems. *The College Mathematics Journal*, 18, 2–17.
- National Voter Registration Act, Public Law 103-31, 103rd Congress (1993).
- NY Election Law §6217 (2021). [https://www.elections.ny.gov/ElectionLaw.html](https://www.elections.ny.gov/ElectionLaw.html)
