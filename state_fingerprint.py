"""
state_fingerprint.py

Multi-state algorithm fingerprint analysis.
Maps known findings from Paquette's state reports against:
  - Algorithm introduction dates
  - Algorithm variants found
  - Known voter registration software vendors
  - HAVA implementation timeline
  - Clone rates and anomaly counts

Goal: identify whether a common upstream codebase or vendor
explains the cross-state pattern.

Sources:
  Paquette (2023) — New York (Caesar Cipher paper)
  Paquette (2024) — Ohio, Texas, Wisconsin, Pennsylvania, Georgia,
                    Arizona, California preliminary reports
  Paquette (2025) — Wisconsin update, system reliability analysis
  Computerworld (2006) — HAVA vendor registry
  EAC HAVA implementation records
"""

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import date


# ---------------------------------------------------------------------------
# DATA STRUCTURES
# ---------------------------------------------------------------------------

@dataclass
class StateRecord:
    state:              str
    abbrev:             str
    hava_db_live:       Optional[int]   # year statewide SVRS went live
    algorithm_intro:    Optional[int]   # year algorithm appears in rolls
    lag_years:          Optional[float] # hava_db_live → algorithm_intro gap
    algorithms_found:   List[str]       # named algorithm variants
    clone_rate_pct:     Optional[float] # % of records that are clones
    anomalous_records:  Optional[int]   # count flagged as suspicious
    svrs_vendor:        Optional[str]   # statewide voter reg system vendor
    notes:              str = ""


# ---------------------------------------------------------------------------
# STATE DATA
# Compiled from Paquette's published reports and HAVA vendor records.
# Fields marked None = not reported / not yet analyzed.
# ---------------------------------------------------------------------------

STATES = [
    StateRecord(
        state="New York",
        abbrev="NY",
        hava_db_live=2006,
        algorithm_intro=2007,
        lag_years=1.0,
        algorithms_found=["Spiral", "Tartan", "Reverse Spiral",
                          "Metronome", "Blur"],
        clone_rate_pct=None,        # paper reports 2M+ clones, no % given
        anomalous_records=2_400_000,
        svrs_vendor="NTS Data Systems (12 counties); custom per county",
        notes="Most thoroughly analyzed. Spiral in 58/62 counties. "
              "Algorithm cutoff date ~6/1/2007 aligns with NYSVoter rollout.",
    ),
    StateRecord(
        state="New Jersey",
        abbrev="NJ",
        hava_db_live=2006,
        algorithm_intro=2007,
        lag_years=1.0,
        algorithms_found=["Shift Cipher"],
        clone_rate_pct=None,
        anomalous_records=102_854,
        svrs_vendor="Accenture (SVRS contract ~2004)",
        notes="Shift cipher variant — simpler than NY Spiral. "
              "~102,854 potentially erroneous/falsified records found.",
    ),
    StateRecord(
        state="Ohio",
        abbrev="OH",
        hava_db_live=2004,
        algorithm_intro=2004,
        lag_years=0.0,
        algorithms_found=["Repunit spacing", "Scatterplot columns/slabs"],
        clone_rate_pct=None,
        anomalous_records=None,
        svrs_vendor="Accenture (SVRS contract, widely criticized)",
        notes="Algorithm appears from Jan 2004 — earliest known introduction. "
              "Coincides with HAVA db launch. 9 counties confirmed including "
              "Allegheny-equivalent (Cuyahoga) and Franklin.",
    ),
    StateRecord(
        state="Pennsylvania",
        abbrev="PA",
        hava_db_live=2006,
        algorithm_intro=2006,
        lag_years=0.0,
        algorithms_found=["Legacy ID → SBOEID mapping", "Repunit spacing"],
        clone_rate_pct=None,
        anomalous_records=115_434,
        svrs_vendor="Accenture (SVRS contract, was late/criticized)",
        notes="9 of 67 counties have algorithm including Allegheny (Pittsburgh) "
              "and Philadelphia (22.45% of all registrations). "
              "115,434 cloned records in current database.",
    ),
    StateRecord(
        state="Wisconsin",
        abbrev="WI",
        hava_db_live=2006,
        algorithm_intro=2016,
        lag_years=10.0,
        algorithms_found=["Multiples of 10", "Random-appearing increment",
                          "CodedID hidden identifier", "Doubles"],
        clone_rate_pct=20.06,
        anomalous_records=444_150,
        svrs_vendor="Accenture (SVRS contract ~2004-2006)",
        notes="Unusual — algorithm shift visible ~2016, much later than others. "
              "31.5% of records end in zero. ~444,150 'doubles' (different voters "
              "sharing functionally identical IDs via leading zero manipulation). "
              "Clone rate peaked at 35.82% in 2021.",
    ),
    StateRecord(
        state="Georgia",
        abbrev="GA",
        hava_db_live=2005,
        algorithm_intro=None,
        lag_years=None,
        algorithms_found=["Repunit spacing (preliminary)"],
        clone_rate_pct=None,
        anomalous_records=None,
        svrs_vendor="GovConnect / Kennesaw State (ELEN system)",
        notes="Preliminary report only. Full analysis not yet published.",
    ),
    StateRecord(
        state="Arizona",
        abbrev="AZ",
        hava_db_live=2005,
        algorithm_intro=None,
        lag_years=None,
        algorithms_found=["Repunit spacing (preliminary)"],
        clone_rate_pct=None,
        anomalous_records=None,
        svrs_vendor="ES&S (EVS)",
        notes="Preliminary report only. Full analysis not yet published.",
    ),
    StateRecord(
        state="Texas",
        abbrev="TX",
        hava_db_live=2006,
        algorithm_intro=None,
        lag_years=None,
        algorithms_found=["Repunit spacing (preliminary)"],
        clone_rate_pct=None,
        anomalous_records=None,
        svrs_vendor="Tyler Technologies (Texas TEAM system)",
        notes="Preliminary report only.",
    ),
    StateRecord(
        state="California",
        abbrev="CA",
        hava_db_live=2006,
        algorithm_intro=2024,
        lag_years=18.0,
        algorithms_found=["Sudden record injection", "Implausible date distribution"],
        clone_rate_pct=None,
        anomalous_records=60_376,
        svrs_vendor="Statewide: VoteCal (Sequoia/Dominion-derived)",
        notes="District 28 analysis only (LA County). 60,376 records appeared "
              "Nov 10-15 2024 during vote counting with unnaturally perfect "
              "RegDate distribution spanning 124 years (1900-present). "
              "Different anomaly type from Spiral — may be separate mechanism.",
    ),
    StateRecord(
        state="North Carolina",
        abbrev="NC",
        hava_db_live=2005,
        algorithm_intro=2006,
        lag_years=1.0,
        algorithms_found=["Repunit spacing"],
        clone_rate_pct=None,
        anomalous_records=None,
        svrs_vendor="SEIMS (State Elections Information Management System)",
        notes="Independent NC researcher confirmed Spiral in Schenectady "
              "and Yates equivalents (mentioned in original NY paper). "
              "Introduction ~2006.",
    ),
    StateRecord(
        state="Hawaii",
        abbrev="HI",
        hava_db_live=2006,
        algorithm_intro=None,
        lag_years=None,
        algorithms_found=["Algorithm present (details unpublished)"],
        clone_rate_pct=None,
        anomalous_records=None,
        svrs_vendor="Hart InterCivic (statewide)",
        notes="Listed in Corsi/Paquette reports as confirmed. "
              "Hart InterCivic is the statewide vendor — notable because "
              "Hart also covers Oklahoma (another listed state).",
    ),
    StateRecord(
        state="Oklahoma",
        abbrev="OK",
        hava_db_live=2006,
        algorithm_intro=None,
        lag_years=None,
        algorithms_found=["Algorithm present (details unpublished)"],
        clone_rate_pct=None,
        anomalous_records=None,
        svrs_vendor="Hart InterCivic (statewide)",
        notes="Listed in Corsi/Paquette reports. "
              "Shares Hart InterCivic statewide vendor with Hawaii.",
    ),
]


# ---------------------------------------------------------------------------
# HAVA CONTEXT
# ---------------------------------------------------------------------------

HAVA_SIGNED         = date(2002, 10, 29)
HAVA_COMPLIANCE_DL  = date(2004, 1, 1)    # deadline for statewide SVRS
HAVA_FULL_IMPL      = date(2006, 12, 31)  # most states fully live by end 2006

KNOWN_SVRS_VENDORS = {
    "Accenture":       ["NJ", "OH", "PA", "WI"],
    "NTS Data Systems":["NY (partial)"],
    "Hart InterCivic": ["HI", "OK", "TX (partial)"],
    "ES&S":            ["AZ", "NC (partial)"],
    "Tyler Technologies": ["TX"],
    "VoteCal/Dominion":["CA"],
    "GovConnect/KSU":  ["GA"],
    "SEIMS":           ["NC"],
}


# ---------------------------------------------------------------------------
# ANALYSIS FUNCTIONS
# ---------------------------------------------------------------------------

def print_timeline():
    """
    Print algorithm introduction dates vs HAVA compliance timeline.
    Shows whether the introduction clusters around HAVA implementation.
    """
    print(f"\n{'='*70}")
    print("ALGORITHM INTRODUCTION VS HAVA IMPLEMENTATION TIMELINE")
    print(f"{'='*70}")
    print(f"\n  HAVA signed:              {HAVA_SIGNED}")
    print(f"  HAVA SVRS deadline:       {HAVA_COMPLIANCE_DL}")
    print(f"  Most states fully live:   {HAVA_FULL_IMPL}")

    print(f"\n  {'State':<16} {'HAVA DB live':<14} {'Algo intro':<12} "
          f"{'Lag (yrs)':<12} {'Vendor'}")
    print(f"  {'-'*72}")

    known = [s for s in STATES if s.hava_db_live and s.algorithm_intro]
    known.sort(key=lambda x: x.algorithm_intro)

    for s in known:
        lag = f"{s.lag_years:.1f}" if s.lag_years is not None else "?"
        vendor_short = (s.svrs_vendor or "Unknown")[:30]
        print(f"  {s.state:<16} {str(s.hava_db_live):<14} "
              f"{str(s.algorithm_intro):<12} {lag:<12} {vendor_short}")

    pending = [s for s in STATES if not s.algorithm_intro]
    if pending:
        print(f"\n  Pending full analysis: "
              f"{', '.join(s.abbrev for s in pending)}")

    # Key finding
    lags = [s.lag_years for s in known if s.lag_years is not None]
    avg_lag = sum(lags) / len(lags) if lags else 0
    print(f"\n  Average lag HAVA live → algorithm intro: {avg_lag:.1f} years")
    print(f"  → Algorithms appear within 0-2 years of HAVA db launch")
    print(f"    in most states. Wisconsin (10yr lag) is the outlier.")


def print_vendor_map():
    """
    Map known SVRS vendors to states with confirmed algorithms.
    Looking for a common vendor fingerprint.
    """
    print(f"\n{'='*70}")
    print("SVRS VENDOR → ALGORITHM PRESENCE MAP")
    print(f"{'='*70}")
    print(f"\n  The key question: does a single vendor explain the pattern?")
    print(f"\n  {'Vendor':<28} {'States with algorithm':}")
    print(f"  {'-'*60}")

    # Accenture is the most interesting — appears in OH, PA, NJ, WI
    accenture_states = [s for s in STATES
                        if s.svrs_vendor and "Accenture" in s.svrs_vendor]
    print(f"\n  {'Accenture':<28} "
          f"{', '.join(s.abbrev for s in accenture_states)}")
    print(f"  {'':28} → Built SVRS for OH, PA, NJ, WI under HAVA funding")
    print(f"  {'':28}   PA project was late and widely criticized")
    print(f"  {'':28}   WI project also criticized; Accenture refunded CO/WY")

    hart_states = [s for s in STATES
                   if s.svrs_vendor and "Hart" in s.svrs_vendor]
    print(f"\n  {'Hart InterCivic':<28} "
          f"{', '.join(s.abbrev for s in hart_states)}")
    print(f"  {'':28} → Statewide in HI and OK (both listed by Paquette)")

    print(f"\n  {'NTS Data Systems':<28} NY (12 counties)")
    print(f"  {'':28} → County-level in NY; not a statewide SVRS vendor")

    print(f"\n  {'Other/Unknown':<28} "
          f"{', '.join(s.abbrev for s in STATES if not s.svrs_vendor or 'Unknown' in s.svrs_vendor)}")

    print(f"\n  ACCENTURE HYPOTHESIS:")
    print(f"  Accenture built the SVRS for at least 4 of the states with")
    print(f"  confirmed algorithms (OH, PA, NJ, WI). If a common codebase")
    print(f"  was used across those projects, a single implementation")
    print(f"  decision could explain the multi-state pattern.")
    print(f"  Accenture's election division was later acquired by — and")
    print(f"  the contracts transferred through — multiple successor firms.")


def print_algorithm_variants():
    """
    Catalog the algorithm variants found across states.
    Are they the same algorithm evolving, or independent implementations?
    """
    print(f"\n{'='*70}")
    print("ALGORITHM VARIANTS BY STATE")
    print(f"{'='*70}")

    # Group by algorithm family
    spiral_family   = []
    repunit_family  = []
    other_family    = []

    for s in STATES:
        algos = " | ".join(s.algorithms_found)
        has_spiral  = any("Spiral" in a or "Caesar" in a or
                          "Shift" in a or "Cipher" in a
                          for a in s.algorithms_found)
        has_repunit = any("Repunit" in a or "repunit" in a or
                          "multiple" in a.lower()
                          for a in s.algorithms_found)

        if has_spiral:
            spiral_family.append(s)
        elif has_repunit:
            repunit_family.append(s)
        else:
            other_family.append(s)

    print(f"\n  FAMILY 1 — Caesar/Shift/Spiral (complex, fully characterized)")
    for s in spiral_family:
        print(f"    {s.abbrev}: {', '.join(s.algorithms_found[:3])}")

    print(f"\n  FAMILY 2 — Repunit spacing (simpler, partially characterized)")
    for s in repunit_family:
        print(f"    {s.abbrev}: {', '.join(s.algorithms_found[:2])}")

    print(f"\n  FAMILY 3 — Other anomalies (different mechanism or early stage)")
    for s in other_family:
        print(f"    {s.abbrev}: {', '.join(s.algorithms_found[:2])}")

    print(f"""
  PATTERN OBSERVATION:
  The most complex variant (NY Spiral with 5 named sub-algorithms)
  appears in the state with the longest analysis time.
  Simpler repunit-spacing patterns appear in states with only
  preliminary reports — this may reflect analysis depth rather
  than actual algorithm complexity.

  Wisconsin's "multiples of 10" and "CodedID" are structurally
  different from the NY Spiral, suggesting either:
    a) A different vendor/codebase was used, OR
    b) The algorithm was modified/updated around 2016 (WI's intro date)
  """)


def print_clone_comparison():
    """
    Compare clone rates across states where data is available.
    """
    print(f"\n{'='*70}")
    print("CLONE RATES & ANOMALOUS RECORD COUNTS BY STATE")
    print(f"{'='*70}")
    print(f"\n  {'State':<16} {'Clone rate':>12}  {'Anomalous records':>20}  Notes")
    print(f"  {'-'*70}")

    for s in sorted(STATES, key=lambda x: x.clone_rate_pct or 0, reverse=True):
        clone = f"{s.clone_rate_pct:.1f}%" if s.clone_rate_pct else "not reported"
        anoms = f"{s.anomalous_records:,}" if s.anomalous_records else "not reported"
        note  = s.notes[:40] + "..." if len(s.notes) > 40 else s.notes
        print(f"  {s.state:<16} {clone:>12}  {anoms:>20}  {note}")

    print(f"""
  NOTE: Clone = voter assigned multiple unique state-level ID numbers.
  Illegal in every state reviewed (equivalent to NY Election Law §6217.6).
  Wisconsin's 20% current clone rate (peaked 35.8% in 2021) is the
  highest reported across all states analyzed.
  """)


def print_common_origin_hypothesis():
    """
    Synthesize the evidence for/against a common origin.
    """
    print(f"\n{'='*70}")
    print("COMMON ORIGIN HYPOTHESIS — EVIDENCE SUMMARY")
    print(f"{'='*70}")
    print(f"""
  SUPPORTS common origin (same vendor/codebase):
  ─────────────────────────────────────────────
  1. TIMING: Algorithm introduction clusters within 0-2 years of
     HAVA-mandated statewide database launch in most states.
     States that launched SVRS earlier (OH: 2004) show earlier
     algorithm introduction. States that launched later show later
     introduction.

  2. ACCENTURE: Built SVRS for OH, PA, NJ, and WI — four of the
     states with confirmed algorithms. A shared codebase across
     those four projects is plausible given Accenture's practice
     of reusing components across state contracts.

  3. REPUNIT CONSTANTS: The same mathematical constants (1,111 /
     1,112 / 111 / 11) appear across NY, NJ, OH, NC — suggesting
     a shared algorithmic specification rather than independent
     reinvention.

  4. STRUCTURE TYPE: The "sort one ID to reveal pattern in other"
     mechanic is present in every fully-analyzed state. This is a
     specific design choice unlikely to be independently invented
     multiple times.

  AGAINST common origin (or complicates the hypothesis):
  ──────────────────────────────────────────────────────
  1. WISCONSIN OUTLIER: WI's algorithm shift appears ~2016, a
     decade after HAVA implementation. If it's the same codebase,
     something triggered a change in 2016 specifically.

  2. CALIFORNIA ANOMALY: CA's District 28 finding (60K records
     appearing during counting with perfect date distribution) is
     structurally different from the Spiral/repunit pattern. May
     be a separate mechanism or a later evolution.

  3. VENDOR COVERAGE GAPS: Not all affected states used Accenture.
     NY used NTS (county-level), AZ used ES&S, TX used Tyler Tech.
     If the algorithm is in all of these, either:
       a) The pattern exists at the state level above the county
          vendor (i.e., a state-level modification after county
          data is submitted), OR
       b) Multiple independent implementations exist, OR
       c) There is a shared upstream component (federal template,
          common library) that none of the vendors wrote themselves.

  4. NY PAPER'S OWN FINDING: Paquette notes that counties using
     their OWN custom software still show The Spiral — implying
     the algorithm is applied AFTER records leave county custody,
     at the state level. This points away from any single county
     vendor and toward the state SVRS layer itself.

  MOST LIKELY HYPOTHESIS (based on available evidence):
  ─────────────────────────────────────────────────────
  The pattern is introduced at the STATE database level, not the
  county level. The common element is not a single vendor but the
  HAVA-mandated statewide database architecture itself — either:
    - A federal template or reference implementation distributed
      to states during HAVA compliance, OR
    - A small number of database consultants/architects who worked
      across multiple state SVRS projects and introduced the same
      pattern in each.

  The Accenture connection is the strongest vendor-level lead,
  covering OH/PA/NJ/WI. Investigating whether those four states
  share identical repunit constants and strip structures would
  either confirm or rule out the shared-codebase hypothesis.
  """)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "="*70)
    print("MULTI-STATE VOTER ROLL ALGORITHM FINGERPRINT ANALYSIS")
    print("Based on Paquette reports (2023-2025) + HAVA vendor records")
    print("="*70)
    print(f"\n  States with confirmed or preliminary findings: {len(STATES)}")
    print(f"  States with full analysis:  "
          f"{sum(1 for s in STATES if len(s.algorithms_found) > 1)}")
    print(f"  States with preliminary only: "
          f"{sum(1 for s in STATES if 'preliminary' in ' '.join(s.algorithms_found).lower())}")

    print_timeline()
    print_vendor_map()
    print_algorithm_variants()
    print_clone_comparison()
    print_common_origin_hypothesis()

    print("\n" + "="*70)
    print("NEXT INVESTIGATIVE STEPS")
    print("="*70)
    print("""
  To test the common-origin hypothesis, the following comparisons
  would be most diagnostic:

  1. Compare exact repunit constants across OH, PA, NJ, WI
     (all Accenture-built). Identical constants → same codebase.

  2. Request Accenture's SVRS contract deliverables via FOIA
     for OH, PA, WI. Look for database schema documentation.

  3. Map the NTS Data Systems product (used in NY counties) to
     see if it was ever licensed to or derived from Accenture code.

  4. Investigate the 2016 WI shift — what changed in WisVote
     (WI's SVRS) in 2016? Version updates? New contractor?

  5. Pull CA's VoteCal schema documentation — VoteCal was built
     on a Sequoia/Dominion-derived platform. If the CA District 28
     anomaly is a different mechanism, it may be a newer evolution.
    """)
