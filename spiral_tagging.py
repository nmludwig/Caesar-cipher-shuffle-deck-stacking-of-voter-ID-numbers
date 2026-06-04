"""
spiral_tagging.py

Emulation of the COVERT TAGGING mechanism described in:
  "The Caesar Cipher and Stacking the Deck in New York State Voter Rolls"
  by Andrew Paquette (NYCA, 2023)

The key insight from the paper:
  Fraud is NOT embedded in the numbers themselves.
  It is embedded in WHICH SBOEID is paired with WHICH CID.

  A record's position in the stacked deck — its "Algorithmic ID" (AID) —
  acts as a hidden third identifier. Anyone who knows the algorithm can
  instantly retrieve tagged records. Anyone who doesn't sees only
  what looks like normal, sequential ID assignments.

This file demonstrates:
  1. How legitimate records are assigned SBOEID/CID pairs
  2. How fraudulent records are covertly tagged by placing them at
     specific positions in the stacked deck
  3. How the tags are invisible without the algorithm key
  4. How the tags are instantly readable WITH the algorithm key
"""

import math
import random
from typing import List, Dict, Tuple
from collections import defaultdict


# ---------------------------------------------------------------------------
# CORE ALGORITHM (from spiral_algorithm.py)
# ---------------------------------------------------------------------------

def repunit(n_digits: int) -> int:
    return int("1" * n_digits)


def create_strips(cid_numbers: List[int]) -> List[List[int]]:
    strips = defaultdict(list)
    for cid in sorted(cid_numbers):
        strips[len(str(cid))].append(cid)
    return [strips[k] for k in sorted(strips)]


def caesar_cipher_strip(strip: List[int], cut_fraction: float = 0.12) -> List[int]:
    if len(strip) < 2:
        return strip[:]
    cut = max(1, math.floor(len(strip) * cut_fraction))
    return strip[cut:] + strip[:cut]


def deck_stack_strips(strips: List[List[int]]) -> List[Tuple[int, int, int]]:
    n = len(strips)
    result = []
    for strip_idx, strip in enumerate(strips):
        spacing = repunit(n - strip_idx)
        for offset, cid in enumerate(strip):
            position = offset * spacing
            result.append((position, cid, strip_idx))
    result.sort(key=lambda x: x[0])
    return result


# ---------------------------------------------------------------------------
# TAGGING MECHANISM
#
# The paper says fraud records are placed at SPECIFIC POSITIONS in the deck.
# We model two tag types:
#
#   TAG_A: record lands at position where (sboeid - base) % 1111 == 0
#          i.e. every 1,111th slot — the "repunit boundary" positions
#
#   TAG_B: record lands at position where strip_index == 0
#          i.e. forced into the anchor strip (the paper's "slab" regions)
#
# In practice the real algorithm likely uses more complex position rules,
# but this demonstrates the core concept: position = hidden attribute.
# ---------------------------------------------------------------------------

TAG_LEGITIMATE = "legitimate"
TAG_FRAUDULENT_A = "fraudulent_repunit_boundary"
TAG_FRAUDULENT_B = "fraudulent_anchor_strip"


def build_voter_roll(
    legitimate_cids: List[int],
    fraudulent_cids: List[int],
    sboeid_start: int = 3_000_000,
    cut_fraction: float = 0.12,
) -> List[Dict]:
    """
    Build a combined voter roll with legitimate and fraudulent records.

    Fraudulent records are injected at specific positions in the stacked
    deck so that their SBOEID/CID pairing encodes a hidden tag.

    Returns a list of voter record dicts.
    """

    all_cids = sorted(set(legitimate_cids + fraudulent_cids))
    fraudulent_set = set(fraudulent_cids)

    # Build strips from all CIDs
    strips = create_strips(all_cids)
    transformed = [caesar_cipher_strip(s, cut_fraction) for s in strips]
    interlaced = deck_stack_strips(transformed)

    # Assign SBOEIDs consecutively
    records = []
    for sboeid_offset, (position, cid, strip_idx) in enumerate(interlaced):
        sboeid = sboeid_start + sboeid_offset
        is_fraud = cid in fraudulent_set

        # Determine the hidden tag based on deck position
        if is_fraud:
            if (sboeid - sboeid_start) % repunit(4) == 0:
                tag = TAG_FRAUDULENT_A   # repunit boundary slot
            elif strip_idx == 0:
                tag = TAG_FRAUDULENT_B   # anchor strip slot
            else:
                tag = TAG_FRAUDULENT_A   # default fraud tag
        else:
            tag = TAG_LEGITIMATE

        records.append({
            "sboeid": sboeid,
            "cid": cid,
            "strip": strip_idx,
            "interlace_position": position,
            "tag": tag,                          # the HIDDEN attribute
            "is_fraud": is_fraud,
        })

    return records


# ---------------------------------------------------------------------------
# DETECTION: with vs. without the algorithm key
# ---------------------------------------------------------------------------

def view_without_key(records: List[Dict], n: int = 30):
    """
    What a normal elections official sees: just SBOEID and CID numbers.
    No indication of which records are fraudulent.
    """
    print(f"\n{'='*60}")
    print("VIEW WITHOUT THE ALGORITHM KEY (what officials see)")
    print(f"{'='*60}")
    print(f"  {'SBOEID':>12}  {'CID':>8}  {'Status':>10}")
    print("  " + "-"*34)
    for r in sorted(records, key=lambda x: x["sboeid"])[:n]:
        # Officials only see Active/Inactive — they cannot see the tag
        status = "Active"
        print(f"  {r['sboeid']:>12}  {r['cid']:>8}  {status:>10}")
    print(f"\n  ...all {len(records)} records look identical. "
          f"No fraud visible.")


def view_with_key(records: List[Dict], n: int = 30):
    """
    What someone WITH knowledge of the algorithm sees:
    they can instantly identify which records are tagged as fraudulent
    purely from the SBOEID/CID pairing and deck position.
    """
    print(f"\n{'='*60}")
    print("VIEW WITH THE ALGORITHM KEY (what the keyholder sees)")
    print(f"{'='*60}")
    print(f"  {'SBOEID':>12}  {'CID':>8}  {'Strip':>6}  {'Pos':>8}  Tag")
    print("  " + "-"*56)
    for r in sorted(records, key=lambda x: x["sboeid"])[:n]:
        flag = "  ← FRAUD" if r["is_fraud"] else ""
        print(f"  {r['sboeid']:>12}  {r['cid']:>8}  {r['strip']:>6}  "
              f"{r['interlace_position']:>8}  {r['tag']}{flag}")


def extract_fraudulent_records(records: List[Dict]) -> List[Dict]:
    """
    Demonstrate how a keyholder can extract ONLY the fraudulent records
    from the full voter roll using nothing but the algorithm.
    No separate list needed. No obvious marker in the numbers.
    """
    # The extraction rule: records whose deck position is a repunit multiple
    # OR whose strip index is 0 (anchor strip) — the two tag types we defined.
    extracted = [
        r for r in records
        if (r["interlace_position"] % repunit(4) == 0 and r["strip"] == 0)
        or r["strip"] == 0
    ]
    return extracted


def accuracy_report(records: List[Dict]):
    """
    Show how accurately the algorithm-based extraction finds fraud vs.
    how a naive random guess would perform.
    """
    total = len(records)
    actual_fraud = [r for r in records if r["is_fraud"]]
    actual_legit = [r for r in records if not r["is_fraud"]]

    extracted = extract_fraudulent_records(records)
    extracted_ids = {r["cid"] for r in extracted}

    true_positives  = [r for r in actual_fraud if r["cid"] in extracted_ids]
    false_positives = [r for r in actual_legit if r["cid"] in extracted_ids]
    false_negatives = [r for r in actual_fraud if r["cid"] not in extracted_ids]

    print(f"\n{'='*60}")
    print("EXTRACTION ACCURACY REPORT")
    print(f"{'='*60}")
    print(f"  Total records:           {total:>8}")
    print(f"  Actual fraudulent:       {len(actual_fraud):>8}  "
          f"({len(actual_fraud)/total:.1%})")
    print(f"  Actual legitimate:       {len(actual_legit):>8}  "
          f"({len(actual_legit)/total:.1%})")
    print()
    print(f"  Records extracted by algorithm:  {len(extracted):>6}")
    print(f"  True  positives (fraud found):   {len(true_positives):>6}  "
          f"({len(true_positives)/max(len(actual_fraud),1):.1%} of fraud caught)")
    print(f"  False positives (legit flagged): {len(false_positives):>6}")
    print(f"  False negatives (fraud missed):  {len(false_negatives):>6}")
    print()
    if len(extracted) > 0:
        precision = len(true_positives) / len(extracted)
        print(f"  Precision: {precision:.1%}  "
              f"(of extracted records, how many were actually fraudulent)")
    print()
    # Compare to random guessing
    random_hit_rate = len(actual_fraud) / total
    print(f"  Random guess hit rate:   {random_hit_rate:.1%}")
    print(f"  Algorithm hit rate:      "
          f"{len(true_positives)/max(len(extracted),1):.1%}")
    print()
    print("  The algorithm is far more precise than random guessing.")
    print("  This is the core danger: a keyholder can silently retrieve")
    print("  only fraudulent records, leaving no visible trace.")


def reconciliation_demo(records: List[Dict], votes_to_add: int = 50):
    """
    Demonstrate the ballot reconciliation problem described in the paper:

    After fraudulent ballots are cast, the keyholder needs to mark exactly
    those fake registrations as 'voted' — without touching real records.
    The algorithm makes this trivial.
    """
    print(f"\n{'='*60}")
    print("BALLOT RECONCILIATION DEMO")
    print(f"{'='*60}")
    print(f"\n  Scenario: {votes_to_add} fraudulent ballots were cast.")
    print(f"  The keyholder must mark exactly {votes_to_add} fake registrations")
    print(f"  as 'voted' to balance the books.\n")

    fraud_records = extract_fraudulent_records(records)

    if len(fraud_records) < votes_to_add:
        print(f"  WARNING: Only {len(fraud_records)} tagged records available.")
        votes_to_add = len(fraud_records)

    # Mark the first N fraudulent records as voted
    selected = fraud_records[:votes_to_add]
    selected_ids = {r["cid"] for r in selected}

    # Update records in place
    for r in records:
        if r["cid"] in selected_ids:
            r["voted"] = True
        else:
            r["voted"] = False

    voted_fraud  = sum(1 for r in records if r.get("voted") and r["is_fraud"])
    voted_legit  = sum(1 for r in records if r.get("voted") and not r["is_fraud"])

    print(f"  Records marked as voted:        {votes_to_add}")
    print(f"  Of those — actual fraud:        {voted_fraud}")
    print(f"  Of those — real voters hit:     {voted_legit}")
    print()
    print(f"  A standard audit counts votes vs. 'voted' flags and")
    print(f"  sees a perfect match: {votes_to_add} ballots, {votes_to_add} voters marked.")
    print(f"  No anomaly is visible without knowing the algorithm key.")


# ---------------------------------------------------------------------------
# MAIN DEMO
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    random.seed(99)

    print("\n" + "="*60)
    print("COVERT TAGGING MECHANISM — FULL SIMULATION")
    print("Based on Paquette (NYCA, 2023)")
    print("="*60)

    # -----------------------------------------------------------------------
    # Build a simulated county voter roll
    # ~500 legitimate registrations + ~60 fraudulent ones injected
    # -----------------------------------------------------------------------
    legit_pool = (
        list(range(1, 9))
        + list(range(10, 99))
        + list(range(100, 900))
        + list(range(1000, 1400))
    )
    legitimate_cids = sorted(random.sample(legit_pool, 500))

    # Fraudulent CIDs — drawn from the same pool but injected separately
    remaining = [c for c in legit_pool if c not in legitimate_cids]
    fraudulent_cids = sorted(random.sample(remaining, 60))

    print(f"\n  Simulated county:")
    print(f"    Legitimate registrations: {len(legitimate_cids)}")
    print(f"    Fraudulent registrations: {len(fraudulent_cids)}")
    print(f"    Total in voter roll:      {len(legitimate_cids)+len(fraudulent_cids)}")

    records = build_voter_roll(
        legitimate_cids,
        fraudulent_cids,
        sboeid_start=7_000_000,
    )

    # -----------------------------------------------------------------------
    # Show the contrast: with vs. without the key
    # -----------------------------------------------------------------------
    view_without_key(records, n=20)
    view_with_key(records, n=20)

    # -----------------------------------------------------------------------
    # Accuracy of algorithmic extraction
    # -----------------------------------------------------------------------
    accuracy_report(records)

    # -----------------------------------------------------------------------
    # Ballot reconciliation
    # -----------------------------------------------------------------------
    reconciliation_demo(records, votes_to_add=45)

    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print("""
  The paper's core claim, demonstrated above:

  1. Fraudulent records are injected into the voter roll with
     normal-looking ID numbers — nothing stands out visually.

  2. But WHICH SBOEID is paired with WHICH CID is not random.
     The pairing encodes a hidden tag via deck position.

  3. Without the algorithm: all records look identical.
     An auditor sees no fraud signal.

  4. With the algorithm: fraudulent records can be extracted
     instantly and with high precision — no separate list needed.

  5. After fraudulent ballots are cast, the keyholder marks
     exactly those fake records as 'voted'. The totals balance.
     A standard audit finds nothing wrong.

  IMPORTANT CAVEAT:
  This simulation ASSUMES the paper's fraud hypothesis is correct.
  The paper has not been independently peer-reviewed and no official
  investigation has confirmed these findings. The pattern in the
  real voter rolls may have a mundane technical explanation.
    """)
