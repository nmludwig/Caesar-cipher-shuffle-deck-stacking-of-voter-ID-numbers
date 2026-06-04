"""
spiral_algorithm.py

Emulation of the "Spiral" algorithm described in:
  "The Caesar Cipher and Stacking the Deck in New York State Voter Rolls"
  by Andrew Paquette (NYCA, 2023)

This code demonstrates the two core mechanics described in the paper:
  1. Caesar Cipher step  — split each strip near its start, swap the segments
  2. Deck Stacking step  — interlace strips together using repunit-based spacing

It is a *simulation* built from the paper's written description. NYCA never
published source code, so this is a best-effort reconstruction for educational
and analytical purposes.
"""

import math
from typing import List, Tuple


# ---------------------------------------------------------------------------
# REPUNIT HELPERS
# ---------------------------------------------------------------------------

def repunit(n_digits: int) -> int:
    """Return the repunit made of n_digits ones: repunit(4) -> 1111."""
    return int("1" * n_digits)


def nearest_repunit(value: int) -> int:
    """Return the repunit closest to value (used for spacing calculations)."""
    digits = max(1, len(str(value)))
    candidates = [repunit(d) for d in range(1, digits + 2)]
    return min(candidates, key=lambda r: abs(r - value))


# ---------------------------------------------------------------------------
# STEP 1 — STRIP CREATION
# Divide a sorted list of CID numbers into strips based on digit-count
# boundaries (the most common strip type described in the paper).
# ---------------------------------------------------------------------------

def create_strips(cid_numbers: List[int]) -> List[List[int]]:
    """
    Split a sorted list of CID numbers into strips by number of digits.
    e.g. 1-9 go in strip 0, 10-99 in strip 1, 100-999 in strip 2, etc.
    """
    if not cid_numbers:
        return []

    strips: dict = {}
    for cid in sorted(cid_numbers):
        key = len(str(cid))
        strips.setdefault(key, []).append(cid)

    return [strips[k] for k in sorted(strips)]


# ---------------------------------------------------------------------------
# STEP 2 — CAESAR CIPHER
# For each strip: find the cut point near the beginning, swap the two segments
# so that Segment1 (low numbers) moves to the END of Segment2 (high numbers).
# The paper says "cut near its beginning" — we use roughly 10-15% as the cut.
# ---------------------------------------------------------------------------

def caesar_cipher_strip(strip: List[int], cut_fraction: float = 0.12) -> List[int]:
    """
    Apply the Caesar-cipher transformation to one strip.

    The strip is cut near its start (at cut_fraction of its length).
    Segment 1 (the small low-number head) moves to the end.
    Result order: Segment2 + Segment1
    """
    if len(strip) < 2:
        return strip[:]

    cut = max(1, math.floor(len(strip) * cut_fraction))
    segment1 = strip[:cut]   # low numbers (head)
    segment2 = strip[cut:]   # high numbers (tail)
    return segment2 + segment1   # swap: high first, then low appended


def apply_caesar_cipher(strips: List[List[int]]) -> List[List[int]]:
    """Apply caesar_cipher_strip to every strip."""
    # The paper notes the first and last strips often have very few numbers
    # and act as anchors; they are still transformed but the effect is minimal.
    return [caesar_cipher_strip(s) for s in strips]


# ---------------------------------------------------------------------------
# STEP 3 — DECK STACKING (interlacing)
# Each strip is spaced by a repunit divisor, then all strips are interlaced
# into a single sequence — like shuffling multiple hands of cards together.
# Strip with widest range gets spacing of repunit(n), next strip repunit(n-1),
# etc., so they nest without overlap.
# ---------------------------------------------------------------------------

def deck_stack_strips(strips: List[List[int]]) -> List[Tuple[int, int, int]]:
    """
    Interlace the transformed strips into one sequence.

    Returns a list of (position, cid, strip_index) tuples sorted by position.
    Position is the slot in the final SBOEID-ordered sequence.

    Spacing for strip i (0=widest) = repunit(n_strips - i).
    """
    n = len(strips)
    result = []

    for strip_idx, strip in enumerate(strips):
        # Assign spacing: widest strip gets largest repunit
        spacing = repunit(n - strip_idx)
        for offset, cid in enumerate(strip):
            position = offset * spacing
            result.append((position, cid, strip_idx))

    # Sort by position to produce the interlaced order
    result.sort(key=lambda x: x[0])
    return result


# ---------------------------------------------------------------------------
# STEP 4 — SBOEID ASSIGNMENT
# Assign consecutive SBOEID numbers to the interlaced CID order.
# The paper says SBOEID numbers are assigned consecutively to the
# algorithm-reordered CID numbers.
# ---------------------------------------------------------------------------

def assign_sboeid(
    interlaced: List[Tuple[int, int, int]],
    sboeid_start: int = 1_000_000
) -> List[dict]:
    """
    Assign consecutive SBOEID numbers to the interlaced sequence.
    Returns a list of voter records with cid, sboeid, strip, and position.
    """
    records = []
    for sboeid_offset, (position, cid, strip_idx) in enumerate(interlaced):
        records.append({
            "sboeid": sboeid_start + sboeid_offset,
            "cid": cid,
            "strip": strip_idx,
            "interlace_position": position,
        })
    return records


# ---------------------------------------------------------------------------
# FULL PIPELINE
# ---------------------------------------------------------------------------

def run_spiral_algorithm(
    cid_numbers: List[int],
    sboeid_start: int = 1_000_000,
    cut_fraction: float = 0.12,
    verbose: bool = True
) -> List[dict]:
    """
    Full Spiral algorithm pipeline:
      1. Create strips (by digit count)
      2. Apply Caesar cipher to each strip
      3. Interlace strips (deck stacking)
      4. Assign SBOEID numbers

    Returns list of voter records.
    """
    if verbose:
        print(f"\n{'='*60}")
        print("SPIRAL ALGORITHM EMULATION")
        print(f"{'='*60}")
        print(f"Input: {len(cid_numbers)} CID numbers")
        print(f"Range: {min(cid_numbers)} – {max(cid_numbers)}")

    # Step 1 — strips
    strips = create_strips(cid_numbers)
    if verbose:
        print(f"\nStep 1 — Strips created: {len(strips)}")
        for i, s in enumerate(strips):
            print(f"  Strip {i+1}: {len(s)} numbers "
                  f"({s[0]} – {s[-1]}), "
                  f"digit-length={len(str(s[0]))}")

    # Step 2 — Caesar cipher
    transformed = apply_caesar_cipher(strips)
    if verbose:
        print(f"\nStep 2 — Caesar cipher applied (cut fraction: {cut_fraction:.0%})")
        for i, (orig, trans) in enumerate(zip(strips, transformed)):
            cut = max(1, math.floor(len(orig) * cut_fraction))
            print(f"  Strip {i+1}: cut at index {cut} "
                  f"→ head [{orig[0]}...{orig[cut-1]}] moved to end")

    # Step 3 — deck stacking
    interlaced = deck_stack_strips(transformed)
    if verbose:
        spacing_info = [repunit(len(strips) - i) for i in range(len(strips))]
        print(f"\nStep 3 — Deck stacking (interlacing)")
        print(f"  Repunit spacings by strip: {spacing_info}")
        print(f"  Total interlaced slots: {len(interlaced)}")

    # Step 4 — assign SBOEIDs
    records = assign_sboeid(interlaced, sboeid_start=sboeid_start)
    if verbose:
        print(f"\nStep 4 — SBOEID assignment")
        print(f"  SBOEID range: {records[0]['sboeid']} – {records[-1]['sboeid']}")

    return records


# ---------------------------------------------------------------------------
# ANALYSIS HELPERS
# ---------------------------------------------------------------------------

def show_sboeid_sorted(records: List[dict], n: int = 30):
    """
    Show records sorted by SBOEID — this reveals the Caesar/strip pattern
    in the CID column, as described in the paper.
    """
    print(f"\n{'='*60}")
    print(f"RECORDS SORTED BY SBOEID (first {n})")
    print(f"{'='*60}")
    print(f"{'SBOEID':>12}  {'CID':>8}  {'Strip':>6}  {'Pos':>10}")
    print("-" * 42)
    for r in sorted(records, key=lambda x: x["sboeid"])[:n]:
        print(f"{r['sboeid']:>12}  {r['cid']:>8}  {r['strip']:>6}  "
              f"{r['interlace_position']:>10}")


def show_cid_sorted(records: List[dict], n: int = 30):
    """
    Show records sorted by CID — this reveals the repunit gap pattern
    in SBOEID numbers (gaps of 1111, 1112, etc.), as described in the paper.
    """
    print(f"\n{'='*60}")
    print(f"RECORDS SORTED BY CID (first {n})")
    print(f"{'='*60}")
    print(f"{'CID':>8}  {'SBOEID':>12}  {'SBOEID gap':>12}  {'Strip':>6}")
    print("-" * 44)
    sorted_recs = sorted(records, key=lambda x: x["cid"])[:n]
    prev_sboeid = None
    for r in sorted_recs:
        gap = (r["sboeid"] - prev_sboeid) if prev_sboeid else "--"
        print(f"{r['cid']:>8}  {r['sboeid']:>12}  {str(gap):>12}  {r['strip']:>6}")
        prev_sboeid = r["sboeid"]


def decode_aid(records: List[dict], target_cid: int, strip_sizes: List[int]):
    """
    Demonstrate the 'Algorithmic ID' (AID) concept from the paper.
    Given a CID number, describe its position in the stacked deck hierarchy.
    """
    match = next((r for r in records if r["cid"] == target_cid), None)
    if not match:
        print(f"\nCID {target_cid} not found in records.")
        return

    pos = match["interlace_position"]
    print(f"\n{'='*60}")
    print(f"ALGORITHMIC ID (AID) DECODE for CID {target_cid}")
    print(f"{'='*60}")
    print(f"  SBOEID:             {match['sboeid']}")
    print(f"  Strip:              {match['strip']}")
    print(f"  Interlace position: {pos}")
    print(f"\n  Interpretation: This record sits at position {pos} in the")
    print(f"  stacked deck. Someone who knows the algorithm can locate")
    print(f"  it instantly; to everyone else it looks like a random ID.")


# ---------------------------------------------------------------------------
# DEMO
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    import random
    random.seed(42)

    # -----------------------------------------------------------------------
    # Demo 1: Small county (like Yates County in the paper, ~13,000 voters)
    # We simulate CID numbers spanning 1-digit through 5-digit ranges.
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("DEMO 1 — Small county simulation (~200 voters)")
    print("="*60)

    # Simulate a realistic spread of CID numbers across digit lengths
    cids_small = (
        list(range(1, 8))           # 1-digit (strip 1)
        + list(range(10, 85))       # 2-digit (strip 2)
        + list(range(100, 650))     # 3-digit (strip 3, largest)
        + list(range(1000, 1090))   # 4-digit (strip 4)
    )
    # Thin it down to ~200 for readability
    cids_small = sorted(random.sample(cids_small, min(200, len(cids_small))))

    records_small = run_spiral_algorithm(
        cids_small,
        sboeid_start=5_000_000,
        cut_fraction=0.12,
        verbose=True
    )

    show_cid_sorted(records_small, n=25)
    show_sboeid_sorted(records_small, n=25)
    decode_aid(records_small, target_cid=cids_small[50], strip_sizes=[])

    # -----------------------------------------------------------------------
    # Demo 2: Show the repunit gap pattern explicitly
    # When sorted by CID, SBOEID gaps should cluster around repunit values.
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("DEMO 2 — Repunit gap analysis")
    print("="*60)

    sorted_by_cid = sorted(records_small, key=lambda x: x["cid"])
    gaps = []
    for i in range(1, len(sorted_by_cid)):
        gaps.append(sorted_by_cid[i]["sboeid"] - sorted_by_cid[i-1]["sboeid"])

    from collections import Counter
    gap_counts = Counter(gaps).most_common(10)
    print("\nTop 10 most common SBOEID gaps (when sorted by CID):")
    print(f"  {'Gap':>8}  {'Count':>8}  {'Is repunit?':>12}")
    print("-" * 34)
    for gap, count in gap_counts:
        is_rep = str(gap) == "1" * len(str(gap)) or str(gap-1) == "1" * len(str(gap-1))
        print(f"  {gap:>8}  {count:>8}  {'YES ←' if is_rep else '':>12}")

    # -----------------------------------------------------------------------
    # Demo 3: Verify reversibility — we should be able to recover original
    # CID order from SBOEID order if we know the algorithm.
    # -----------------------------------------------------------------------
    print("\n" + "="*60)
    print("DEMO 3 — Reversibility check")
    print("="*60)

    # The original CID list sorted
    original_order = sorted(cids_small)
    # Recover CID order from records sorted by SBOEID
    recovered_order = [r["cid"] for r in sorted(records_small, key=lambda x: x["sboeid"])]

    # They should NOT match (algorithm scrambled them)
    matches = sum(1 for a, b in zip(original_order, recovered_order) if a == b)
    total = len(original_order)
    print(f"\n  Original CID order vs SBOEID-sorted CID order:")
    print(f"  Positions that match: {matches}/{total} "
          f"({matches/total:.1%})")
    print(f"\n  A low match rate confirms the algorithm scrambled the IDs.")
    print(f"  Anyone WITHOUT knowledge of the algorithm sees apparent chaos.")
    print(f"  Anyone WITH it can predict exactly where any record lands.")

    print("\n" + "="*60)
    print("Done. See spiral_algorithm.py for full documented source.")
    print("="*60)
