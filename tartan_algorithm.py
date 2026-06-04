"""
tartan_algorithm.py

Emulation and analysis of the "Tartan" algorithm described in:
  "The Caesar Cipher and Stacking the Deck in New York State Voter Rolls"
  by Andrew Paquette (NYCA, 2023)

The Tartan algorithm governs the Out-of-Range (OOR) partition of NY voter rolls.
Unlike The Spiral (which was fully solved), Tartan was only partially analyzed.

What the paper established:
  - OOR-High range: SBOEID 40,481,162 – 99,999,999 (8,940,618 records)
  - OOR-Low range:  SBOEID 0 – 8,502,558 (only 2,436 records)
  - OOR records are NOT segregated by county (unlike IR/Spiral records)
  - A scatterplot of OOR SBOEID (Y) vs CID (X) reveals two formations:
      COLUMNS  = vertical orientation  → Active records
      SLABS    = horizontal orientation → Purged records (99.9%+)
  - No active records appear in slab regions
  - Two values predict purge status with high accuracy:
      partition=OOR + RegDate < 6/1/2007 → 98.30% purged
      (vs IR + same RegDate → only 42.45% purged)
  - Slab regions contain disproportionate numbers of CLONES
    (voters with multiple illegal SBOEID numbers)
  - Nassau County slab example: 176,090 records, >99.9% purged,
    27.38% identified as clones

This file:
  1. Simulates the Tartan number assignment pattern
  2. Models column vs. slab formations
  3. Demonstrates the purge-status prediction capability
  4. Visualizes the scatterplot structure described in the paper
  5. Attempts to partially reverse-engineer the unsolved Tartan rules
"""

import math
import random
from typing import List, Dict, Tuple
from collections import defaultdict
from datetime import date, timedelta


# ---------------------------------------------------------------------------
# CONSTANTS (from the paper)
# ---------------------------------------------------------------------------

OOR_LOW_MIN   = 0
OOR_LOW_MAX   = 8_502_558
IR_MIN        = 8_502_559
IR_MAX        = 40_481_161
OOR_HIGH_MIN  = 40_481_162
OOR_HIGH_MAX  = 99_999_999

ALGORITHM_INTRODUCTION_DATE = date(2007, 6, 1)   # RegDate cutoff from paper

# Nassau County slab stats from paper
NASSAU_SLAB_TOTAL    = 176_090
NASSAU_SLAB_PURGED   = 175_945   # 99.9%+
NASSAU_SLAB_CLONES   = 48_181    # 27.38% of slab records


# ---------------------------------------------------------------------------
# FORMATION TYPES
# The core Tartan discovery: scatterplot orientation predicts status
# ---------------------------------------------------------------------------

FORMATION_COLUMN = "column"   # vertical  → Active
FORMATION_SLAB   = "slab"     # horizontal → Purged


def determine_formation(cid: int, sboeid: int,
                         cid_range: Tuple[int,int],
                         sboeid_range: Tuple[int,int]) -> str:
    """
    Determine if a CID/SBOEID pair falls in a column or slab region.

    In the paper's scatterplot (CID on X, SBOEID on Y):
      - COLUMNS: narrow CID range, wide SBOEID range  (tall and thin)
      - SLABS:   wide CID range,  narrow SBOEID range (short and wide)

    We model this by checking whether the record's position is
    dominated by CID variance (column) or SBOEID variance (slab).
    """
    cid_min, cid_max = cid_range
    sboeid_min, sboeid_max = sboeid_range

    cid_span   = max(cid_max - cid_min, 1)
    sboeid_span = max(sboeid_max - sboeid_min, 1)

    # Normalize positions within their respective ranges
    cid_norm    = (cid - cid_min)    / cid_span
    sboeid_norm = (sboeid - sboeid_min) / sboeid_span

    # Column: CID is tightly clustered (low normalized variance within group)
    # Slab:   SBOEID is tightly clustered
    # We use modular arithmetic to simulate the banding
    cid_band    = int(cid_norm    * 100) % 10
    sboeid_band = int(sboeid_norm * 100) % 10

    # Slabs occur where SBOEID values are concentrated in horizontal bands
    # The paper shows these as distinct horizontal stripes
    if sboeid_band < 3:   # ~30% of the space → slab regions
        return FORMATION_SLAB
    return FORMATION_COLUMN


# ---------------------------------------------------------------------------
# TARTAN ALGORITHM SIMULATION
#
# The paper describes Tartan as "appearing to randomize" but having structure.
# Based on the column/slab pattern, we model it as:
#
#   1. CID numbers are assigned across ALL counties (no county segregation)
#   2. SBOEID numbers in OOR-High are placed in one of two formation types:
#      - Column formations: CID clusters vary, SBOEID spans wide range
#        → These become Active records
#      - Slab formations:   SBOEID clusters in narrow bands, CID varies widely
#        → These are assigned Purged status AT CREATION (key anomaly)
#   3. RegDate < 6/1/2007 strongly predicts OOR assignment
#      (suggesting OOR records predate the algorithm's public introduction)
# ---------------------------------------------------------------------------

def generate_random_regdate(before_cutoff: bool = True) -> date:
    """Generate a random registration date before or after the 2007 cutoff."""
    if before_cutoff:
        start = date(1950, 1, 1)
        end   = ALGORITHM_INTRODUCTION_DATE
    else:
        start = ALGORITHM_INTRODUCTION_DATE
        end   = date(2021, 10, 21)   # paper's database date
    delta = (end - start).days
    return start + timedelta(days=random.randint(0, delta))


def assign_tartan_sboeid(cid: int, county_code: int,
                          formation: str,
                          base: int = OOR_HIGH_MIN) -> int:
    """
    Assign an OOR-High SBOEID based on the Tartan pattern.

    Column records: SBOEID varies widely, CID is the anchor
    Slab records:   SBOEID is in a narrow horizontal band regardless of CID
    """
    oor_range = OOR_HIGH_MAX - OOR_HIGH_MIN

    if formation == FORMATION_COLUMN:
        # Column: SBOEID is a function of CID with wide spread
        # Each county gets a vertical "stripe" in the scatterplot
        county_offset = (county_code * 500_000) % oor_range
        cid_component = (cid * 1_117) % oor_range   # pseudo-random spread
        sboeid = base + (county_offset + cid_component) % oor_range

    else:  # SLAB
        # Slab: SBOEID is locked to a narrow horizontal band
        # CID can vary widely — this is what creates the horizontal stripe
        slab_band = (county_code % 8) * 2_000_000   # 8 possible slab bands
        slab_offset = cid % 50_000                   # small variation within band
        sboeid = base + slab_band + slab_offset

    return sboeid


def build_oor_roll(
    n_records: int = 500,
    pct_slab: float = 0.30,
    pct_pre_cutoff: float = 0.85,
    n_counties: int = 62,
    seed: int = 7,
) -> List[Dict]:
    """
    Build a simulated OOR-High partition voter roll using Tartan rules.

    Parameters:
      n_records:       total records to generate
      pct_slab:        fraction placed in slab formations (~30% in paper)
      pct_pre_cutoff:  fraction with RegDate before 6/1/2007
      n_counties:      number of counties (all mixed together in OOR)
      seed:            random seed

    Returns list of voter record dicts.
    """
    random.seed(seed)
    records = []

    n_slab   = int(n_records * pct_slab)
    n_column = n_records - n_slab

    # CID ranges vary widely in OOR (no county segregation)
    # We simulate alphanumeric and numeric CIDs
    def random_cid():
        style = random.choice(["numeric_5", "numeric_9", "alpha"])
        if style == "numeric_5":
            return random.randint(10000, 99999)
        elif style == "numeric_9":
            return random.randint(100000000, 999999999)
        else:
            return random.randint(1000, 9999)   # simplified alphanumeric

    for i in range(n_records):
        is_slab       = (i < n_slab)
        formation     = FORMATION_SLAB if is_slab else FORMATION_COLUMN
        county_code   = random.randint(1, n_counties)
        cid           = random_cid()
        before_cutoff = random.random() < pct_pre_cutoff
        regdate       = generate_random_regdate(before_cutoff=before_cutoff)

        sboeid = assign_tartan_sboeid(cid, county_code, formation)

        # Purge status: paper shows slab+pre-cutoff → 98.3% purged
        # Column+pre-cutoff → 42.45% purged (much lower)
        if formation == FORMATION_SLAB:
            purge_prob = 0.999 if before_cutoff else 0.50
        else:
            purge_prob = 0.424 if before_cutoff else 0.202

        status = "Purged" if random.random() < purge_prob else "Active"

        # Clones: slab records have ~27% clone rate pre-cutoff
        clone_prob = 0.2738 if (formation == FORMATION_SLAB and before_cutoff) else 0.05
        is_clone = random.random() < clone_prob

        records.append({
            "sboeid":       sboeid,
            "cid":          cid,
            "county_code":  county_code,
            "regdate":      regdate,
            "formation":    formation,
            "status":       status,
            "is_clone":     is_clone,
            "pre_cutoff":   before_cutoff,
        })

    return records


# ---------------------------------------------------------------------------
# TARTAN DETECTION / ANALYSIS
# ---------------------------------------------------------------------------

def predict_purge_status(record: Dict) -> Tuple[str, float]:
    """
    Implement the paper's two-variable prediction rule:
      OOR partition + RegDate < 6/1/2007 → predict Purged (98.3% accuracy)

    Returns (prediction, confidence).
    """
    if record["pre_cutoff"]:
        if record["formation"] == FORMATION_SLAB:
            return "Purged", 0.999
        else:
            return "Purged", 0.424   # less confident for column
    else:
        return "Active", 0.798   # post-cutoff → likely active


def formation_accuracy_report(records: List[Dict]):
    """
    Show how well formation type alone predicts purge status —
    the core Tartan finding from the paper.
    """
    print(f"\n{'='*60}")
    print("TARTAN: FORMATION → PURGE STATUS PREDICTION")
    print(f"{'='*60}")

    slab_records   = [r for r in records if r["formation"] == FORMATION_SLAB]
    column_records = [r for r in records if r["formation"] == FORMATION_COLUMN]

    slab_purged   = sum(1 for r in slab_records   if r["status"] == "Purged")
    column_purged = sum(1 for r in column_records if r["status"] == "Purged")

    print(f"\n  SLAB formation records:    {len(slab_records):>6}")
    if slab_records:
        print(f"    Purged:                  {slab_purged:>6}  "
              f"({slab_purged/len(slab_records):.1%})")
        print(f"    Active:                  {len(slab_records)-slab_purged:>6}  "
              f"({(len(slab_records)-slab_purged)/len(slab_records):.1%})")

    print(f"\n  COLUMN formation records:  {len(column_records):>6}")
    if column_records:
        print(f"    Purged:                  {column_purged:>6}  "
              f"({column_purged/len(column_records):.1%})")
        print(f"    Active:                  {len(column_records)-column_purged:>6}  "
              f"({(len(column_records)-column_purged)/len(column_records):.1%})")

    print(f"\n  Key anomaly from the paper:")
    print(f"  Purged records supposedly derived from records that were")
    print(f"  once Active. But slab records appear to have been created")
    print(f"  as Purged — they were NEVER Active.")
    print(f"  → How did the system know they were ineligible at creation?")


def regdate_partition_analysis(records: List[Dict]):
    """
    Reproduce the paper's Table 7:
    IR vs OOR purge rates, split by RegDate cutoff.
    """
    print(f"\n{'='*60}")
    print("TARTAN: REGDATE + PARTITION → PURGE PREDICTION (Table 7)")
    print(f"{'='*60}")

    pre  = [r for r in records if r["pre_cutoff"]]
    post = [r for r in records if not r["pre_cutoff"]]

    def stats(recs):
        if not recs:
            return 0, 0, 0.0
        purged = sum(1 for r in recs if r["status"] == "Purged")
        return len(recs), purged, purged/len(recs)

    pre_n, pre_p, pre_pct   = stats(pre)
    post_n, post_p, post_pct = stats(post)

    print(f"\n  {'':30} {'Pre-6/1/2007':>14} {'Post-6/1/2007':>14}")
    print(f"  {'-'*60}")
    print(f"  {'OOR records (simulated)':30} {pre_n:>14,} {post_n:>14,}")
    print(f"  {'Purged':30} {pre_p:>14,} {post_p:>14,}")
    print(f"  {'Purge rate':30} {pre_pct:>13.1%} {post_pct:>13.1%}")
    print(f"\n  Paper's actual figures (Nassau OOR):")
    print(f"  {'OOR Pre-6/1/2007 purge rate':30} {'98.30%':>14}")
    print(f"  {'IR  Pre-6/1/2007 purge rate':30} {'42.45%':>14}")
    print(f"  {'OOR Post-6/1/2007 purge rate':30} {'20.17%':>14}")
    print(f"  {'IR  Post-6/1/2007 purge rate':30} {'32.02%':>14}")
    print(f"\n  The massive gap (98.3% vs 42.5%) for the same RegDate range")
    print(f"  means partition membership — not age — drives purge status.")
    print(f"  That should be impossible in a legitimate system.")


def clone_analysis(records: List[Dict]):
    """
    Show the clone concentration in slab regions, matching the paper's
    Nassau County finding (27.38% clones in pre-cutoff slab records).
    """
    print(f"\n{'='*60}")
    print("TARTAN: CLONE CONCENTRATION IN SLAB REGIONS")
    print(f"{'='*60}")

    slab_pre  = [r for r in records if r["formation"]==FORMATION_SLAB and r["pre_cutoff"]]
    slab_post = [r for r in records if r["formation"]==FORMATION_SLAB and not r["pre_cutoff"]]
    col_pre   = [r for r in records if r["formation"]==FORMATION_COLUMN and r["pre_cutoff"]]

    def clone_rate(recs):
        if not recs: return 0.0
        return sum(1 for r in recs if r["is_clone"]) / len(recs)

    print(f"\n  {'Segment':40} {'Clone rate':>12}")
    print(f"  {'-'*54}")
    print(f"  {'Slab  + pre-6/1/2007  (paper: 28.13%)':40} {clone_rate(slab_pre):>11.1%}")
    print(f"  {'Slab  + post-6/1/2007 (paper: 10.75%)':40} {clone_rate(slab_post):>11.1%}")
    print(f"  {'Column + pre-6/1/2007 (paper: ~5%)':40} {clone_rate(col_pre):>11.1%}")
    print(f"\n  Clones = voters with multiple unique SBOEID numbers.")
    print(f"  Illegal under NY Election Law §6217.6.")
    print(f"  Their concentration in slab regions suggests slabs are")
    print(f"  purpose-built storage for fraudulent/duplicate records.")


def attempt_tartan_decode(records: List[Dict], n_show: int = 20):
    """
    Attempt to identify the structural rule behind Tartan by looking
    for mathematical patterns in slab SBOEID assignments.

    The paper says Tartan 'appears random' but has non-random structure.
    We look for:
      - Modular patterns in SBOEID values
      - Repunit-based spacing (like The Spiral)
      - County-code encoding
    """
    print(f"\n{'='*60}")
    print("TARTAN: ATTEMPTED PARTIAL DECODE")
    print(f"{'='*60}")

    slab_records = sorted(
        [r for r in records if r["formation"] == FORMATION_SLAB],
        key=lambda x: x["sboeid"]
    )

    if not slab_records:
        print("  No slab records found.")
        return

    print(f"\n  Analyzing {len(slab_records)} slab records for hidden structure...")

    # Test 1: Gaps between consecutive slab SBOEIDs — are they repunit-like?
    gaps = []
    for i in range(1, len(slab_records)):
        gaps.append(slab_records[i]["sboeid"] - slab_records[i-1]["sboeid"])

    from collections import Counter
    gap_counts = Counter(gaps).most_common(8)
    print(f"\n  Top SBOEID gaps in slab records:")
    print(f"  {'Gap':>12}  {'Count':>8}  {'Pattern?':>12}")
    print(f"  {'-'*36}")
    for gap, count in gap_counts:
        # Check if gap is repunit-related
        gap_str = str(abs(gap))
        is_repunit = len(set(gap_str)) == 1
        is_repunit_plus1 = len(set(str(abs(gap)-1))) == 1
        pattern = "REPUNIT" if is_repunit else ("REPUNIT+1" if is_repunit_plus1 else "")
        print(f"  {gap:>12,}  {count:>8}  {pattern:>12}")

    # Test 2: SBOEID modulo repunits — do slabs cluster at multiples?
    print(f"\n  Slab SBOEID values mod common repunits:")
    print(f"  {'Repunit':>10}  {'Mean remainder':>16}  {'Std dev':>10}")
    print(f"  {'-'*40}")
    import statistics
    for r_digits in [4, 5, 6]:
        ru = int("1" * r_digits)
        remainders = [rec["sboeid"] % ru for rec in slab_records]
        if len(remainders) > 1:
            mean_r = statistics.mean(remainders)
            std_r  = statistics.stdev(remainders)
            clustered = "← CLUSTERED" if std_r < ru * 0.2 else ""
            print(f"  {ru:>10,}  {mean_r:>16,.0f}  {std_r:>10,.0f}  {clustered}")

    # Test 3: County code correlation
    print(f"\n  County code distribution in slab vs column:")
    slab_counties   = Counter(r["county_code"] for r in slab_records)
    col_counties    = Counter(r["county_code"] for r in records
                              if r["formation"] == FORMATION_COLUMN)
    print(f"  Unique counties in slabs:   {len(slab_counties)}")
    print(f"  Unique counties in columns: {len(col_counties)}")
    print(f"  (Paper: OOR mixes all 62 counties — no county segregation)")

    # Test 4: Show first N slab records to look for visual patterns
    print(f"\n  First {n_show} slab records (sorted by SBOEID):")
    print(f"  {'SBOEID':>12}  {'CID':>12}  {'County':>8}  {'RegDate':>12}  Status")
    print(f"  {'-'*58}")
    for r in slab_records[:n_show]:
        print(f"  {r['sboeid']:>12,}  {r['cid']:>12,}  "
              f"{r['county_code']:>8}  {str(r['regdate']):>12}  {r['status']}")

    print(f"\n  CONCLUSION: Tartan remains partially unsolved.")
    print(f"  The column/slab structure is clear, but the exact rule")
    print(f"  determining which records fall in slabs vs columns has")
    print(f"  not been reverse-engineered from the paper's description.")
    print(f"  The paper itself acknowledges Tartan is 'as yet unsolved'.")


# ---------------------------------------------------------------------------
# SCATTERPLOT (ASCII art — approximates the paper's Figures 6, 7, 8)
# ---------------------------------------------------------------------------

def ascii_scatterplot(records: List[Dict], width: int = 60, height: int = 25):
    """
    ASCII approximation of the paper's OOR scatterplot.
    X axis = CID (log scale), Y axis = SBOEID.
    Columns show as vertical clusters, slabs as horizontal bands.
    """
    print(f"\n{'='*60}")
    print("TARTAN: SCATTERPLOT (ASCII approximation of paper Fig. 6-8)")
    print(f"{'='*60}")

    import math as m

    cids    = [r["cid"]    for r in records]
    sboeids = [r["sboeid"] for r in records]

    cid_min, cid_max       = min(cids), max(cids)
    sboeid_min, sboeid_max = min(sboeids), max(sboeids)

    # Use log scale for CID (paper uses log X axis)
    def to_x(cid):
        if cid <= 0: return 0
        log_min = m.log10(max(cid_min, 1))
        log_max = m.log10(max(cid_max, 2))
        log_val = m.log10(max(cid, 1))
        return int((log_val - log_min) / (log_max - log_min) * (width - 1))

    def to_y(sboeid):
        return int((sboeid - sboeid_min) / max(sboeid_max - sboeid_min, 1) * (height - 1))

    # Build grid
    grid = [[" "] * width for _ in range(height)]
    for r in records:
        x = to_x(r["cid"])
        y = height - 1 - to_y(r["sboeid"])  # flip Y
        x = max(0, min(width-1, x))
        y = max(0, min(height-1, y))
        if r["status"] == "Active":
            grid[y][x] = "│" if r["formation"] == FORMATION_COLUMN else "─"
        else:
            grid[y][x] = "+" if r["formation"] == FORMATION_SLAB else "·"

    print(f"\n  SBOEID")
    print(f"  {sboeid_max:>12,} ┐")
    for row in grid:
        print(f"  {'':12}  │{''.join(row)}│")
    print(f"  {sboeid_min:>12,} ┘")
    print(f"  {'':14}" + "─"*width)
    print(f"  {'CID (log scale)':>{width//2+14}}")
    print(f"\n  Legend:  │ = Active column   · = Purged column")
    print(f"           ─ = Active slab     + = Purged slab")
    print(f"\n  Note: Active slabs (─) should be ABSENT per the paper.")
    active_slabs = sum(1 for r in records
                       if r["formation"]==FORMATION_SLAB and r["status"]=="Active")
    print(f"  Active slab records in this simulation: {active_slabs}")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(7)

    print("\n" + "="*60)
    print("TARTAN ALGORITHM — OOR PARTITION ANALYSIS")
    print("Based on Paquette (NYCA, 2023)")
    print("="*60)
    print(f"\n  OOR-High range: {OOR_HIGH_MIN:,} – {OOR_HIGH_MAX:,}")
    print(f"  OOR-Low range:  {OOR_LOW_MIN:,} – {OOR_LOW_MAX:,}")
    print(f"  RegDate cutoff: {ALGORITHM_INTRODUCTION_DATE}")
    print(f"  Paper's Nassau County slab stats:")
    print(f"    Total slab records:  {NASSAU_SLAB_TOTAL:,}")
    print(f"    Purged:              {NASSAU_SLAB_PURGED:,} (99.9%+)")
    print(f"    Clones:              {NASSAU_SLAB_CLONES:,} (27.38%)")

    # Build simulated OOR roll
    records = build_oor_roll(n_records=600, pct_slab=0.30, pct_pre_cutoff=0.80)

    print(f"\n  Simulated OOR records: {len(records)}")
    print(f"  Slab formations:       "
          f"{sum(1 for r in records if r['formation']==FORMATION_SLAB)}")
    print(f"  Column formations:     "
          f"{sum(1 for r in records if r['formation']==FORMATION_COLUMN)}")

    # Run all analyses
    formation_accuracy_report(records)
    regdate_partition_analysis(records)
    clone_analysis(records)
    attempt_tartan_decode(records, n_show=15)
    ascii_scatterplot(records, width=55, height=20)

    print("\n" + "="*60)
    print("SUMMARY: WHAT TARTAN TELLS US")
    print("="*60)
    print("""
  The Tartan algorithm (OOR partition) differs from The Spiral (IR):

  The Spiral — SOLVED:
    Governs 56.93% of all records (In-Range partition)
    Restructures ID numbers to create hidden positional tags
    Used to covertly identify records for later retrieval

  Tartan — PARTIALLY SOLVED:
    Governs OOR partition (no county segregation)
    Creates two visual formations in a SBOEID-vs-CID scatterplot:
      COLUMNS → Active records
      SLABS   → Purged records (born purged, never active)
    Slab records have disproportionate clone concentrations
    RegDate + partition predicts purge status with 98.3% accuracy

  The critical unanswered question:
    Records in slab regions were assigned Purged status
    at the moment of their creation. This is anomalous because
    purged records should be derived from formerly-active records.
    Something — or someone — knew these records were fraudulent
    before they ever appeared in the voter rolls.

  CAVEAT: This remains a simulation. The paper itself states
  Tartan is 'as yet unsolved'. No official investigation has
  confirmed these findings.
    """)
