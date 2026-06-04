"""
app.py — Voter Roll Algorithm Analysis Web App
Flask backend serving the Spiral, Tartan, and State Fingerprint analyses.
"""

from flask import Flask, render_template, jsonify, request
import math, random, json
from collections import Counter, defaultdict
from datetime import date, timedelta

app = Flask(__name__)

# ── helpers from spiral_algorithm.py ────────────────────────────────────────

def repunit(n):
    return int("1" * n)

def create_strips(cids):
    strips = defaultdict(list)
    for c in sorted(cids):
        strips[len(str(c))].append(c)
    return [strips[k] for k in sorted(strips)]

def caesar_cipher_strip(strip, cut_fraction=0.12):
    if len(strip) < 2:
        return strip[:]
    cut = max(1, math.floor(len(strip) * cut_fraction))
    return strip[cut:] + strip[:cut]

def deck_stack_strips(strips):
    n = len(strips)
    result = []
    for idx, strip in enumerate(strips):
        spacing = repunit(n - idx)
        for offset, cid in enumerate(strip):
            result.append((offset * spacing, cid, idx))
    result.sort(key=lambda x: x[0])
    return result

def run_spiral(cids, sboeid_start=5_000_000):
    strips     = create_strips(cids)
    transformed = [caesar_cipher_strip(s) for s in strips]
    interlaced  = deck_stack_strips(transformed)
    records = []
    for i, (pos, cid, strip_idx) in enumerate(interlaced):
        records.append({
            "sboeid": sboeid_start + i,
            "cid":    cid,
            "strip":  strip_idx,
            "pos":    pos,
        })
    return records, strips

# ── state fingerprint data (inline from state_fingerprint.py) ───────────────

STATE_DATA = [
    {"state":"New York",      "abbrev":"NY","hava":2006,"algo_intro":2007,"lag":1.0,
     "algorithms":["Spiral","Tartan","Reverse Spiral","Metronome","Blur"],
     "anomalous":2400000,"clone_pct":None,
     "vendor":"NTS Data Systems (12 counties)"},
    {"state":"New Jersey",    "abbrev":"NJ","hava":2006,"algo_intro":2007,"lag":1.0,
     "algorithms":["Shift Cipher"],
     "anomalous":102854,"clone_pct":None,
     "vendor":"Accenture"},
    {"state":"Ohio",          "abbrev":"OH","hava":2004,"algo_intro":2004,"lag":0.0,
     "algorithms":["Repunit spacing","Columns/Slabs"],
     "anomalous":None,"clone_pct":None,
     "vendor":"Accenture"},
    {"state":"Pennsylvania",  "abbrev":"PA","hava":2006,"algo_intro":2006,"lag":0.0,
     "algorithms":["Legacy ID mapping","Repunit spacing"],
     "anomalous":115434,"clone_pct":None,
     "vendor":"Accenture"},
    {"state":"Wisconsin",     "abbrev":"WI","hava":2006,"algo_intro":2016,"lag":10.0,
     "algorithms":["Multiples of 10","CodedID","Doubles"],
     "anomalous":444150,"clone_pct":20.06,
     "vendor":"Accenture"},
    {"state":"Georgia",       "abbrev":"GA","hava":2005,"algo_intro":None,"lag":None,
     "algorithms":["Repunit spacing (preliminary)"],
     "anomalous":None,"clone_pct":None,
     "vendor":"GovConnect/KSU"},
    {"state":"Arizona",       "abbrev":"AZ","hava":2005,"algo_intro":None,"lag":None,
     "algorithms":["Repunit spacing (preliminary)"],
     "anomalous":None,"clone_pct":None,
     "vendor":"ES&S"},
    {"state":"Texas",         "abbrev":"TX","hava":2006,"algo_intro":None,"lag":None,
     "algorithms":["Repunit spacing (preliminary)"],
     "anomalous":None,"clone_pct":None,
     "vendor":"Tyler Technologies"},
    {"state":"California",    "abbrev":"CA","hava":2006,"algo_intro":2024,"lag":18.0,
     "algorithms":["Record injection","Implausible date distribution"],
     "anomalous":60376,"clone_pct":None,
     "vendor":"VoteCal / Dominion-derived"},
    {"state":"North Carolina","abbrev":"NC","hava":2005,"algo_intro":2006,"lag":1.0,
     "algorithms":["Repunit spacing"],
     "anomalous":None,"clone_pct":None,
     "vendor":"SEIMS"},
    {"state":"Hawaii",        "abbrev":"HI","hava":2006,"algo_intro":None,"lag":None,
     "algorithms":["Confirmed (unpublished)"],
     "anomalous":None,"clone_pct":None,
     "vendor":"Hart InterCivic"},
    {"state":"Oklahoma",      "abbrev":"OK","hava":2006,"algo_intro":None,"lag":None,
     "algorithms":["Confirmed (unpublished)"],
     "anomalous":None,"clone_pct":None,
     "vendor":"Hart InterCivic"},
]

# ── routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/spiral", methods=["POST"])
def api_spiral():
    """Run spiral algorithm on user-supplied or auto-generated CID list."""
    data     = request.get_json(silent=True) or {}
    n        = min(int(data.get("n", 200)), 500)
    seed     = int(data.get("seed", 42))
    random.seed(seed)

    pool = (list(range(1, 9)) + list(range(10, 99)) +
            list(range(100, 900)) + list(range(1000, 1400)))
    cids = sorted(random.sample(pool, min(n, len(pool))))

    records, strips = run_spiral(cids)

    # Gap analysis
    by_cid = sorted(records, key=lambda r: r["cid"])
    gaps   = [by_cid[i]["sboeid"] - by_cid[i-1]["sboeid"]
              for i in range(1, len(by_cid))]
    gap_counts = Counter(gaps).most_common(8)

    # Scramble check
    orig      = sorted(cids)
    recovered = [r["cid"] for r in sorted(records, key=lambda r: r["sboeid"])]
    matches   = sum(1 for a, b in zip(orig, recovered) if a == b)

    return jsonify({
        "records":    records[:50],          # first 50 for display
        "total":      len(records),
        "n_strips":   len(strips),
        "strip_sizes":[len(s) for s in strips],
        "gap_counts": [{"gap": g, "count": c} for g, c in gap_counts],
        "scramble_pct": round(100 * (1 - matches / len(orig)), 1),
        "sboeid_range": [records[0]["sboeid"], records[-1]["sboeid"]],
    })


@app.route("/api/tagging", methods=["POST"])
def api_tagging():
    """Simulate covert tagging: legit vs fraudulent records."""
    data        = request.get_json(silent=True) or {}
    n_legit     = min(int(data.get("n_legit", 300)), 800)
    n_fraud     = min(int(data.get("n_fraud", 40)),  200)
    seed        = int(data.get("seed", 99))
    random.seed(seed)

    pool = (list(range(1,9)) + list(range(10,99)) +
            list(range(100,900)) + list(range(1000,1400)))
    legit_cids = sorted(random.sample(pool, min(n_legit, len(pool))))
    remaining  = [c for c in pool if c not in set(legit_cids)]
    fraud_cids = sorted(random.sample(remaining, min(n_fraud, len(remaining))))

    all_cids     = sorted(set(legit_cids + fraud_cids))
    fraud_set    = set(fraud_cids)
    strips       = create_strips(all_cids)
    transformed  = [caesar_cipher_strip(s) for s in strips]
    interlaced   = deck_stack_strips(transformed)

    records = []
    for i, (pos, cid, strip_idx) in enumerate(interlaced):
        sboeid   = 7_000_000 + i
        is_fraud = cid in fraud_set
        records.append({
            "sboeid":   sboeid,
            "cid":      cid,
            "strip":    strip_idx,
            "pos":      pos,
            "is_fraud": is_fraud,
        })

    # Extraction: anchor strip (strip 0) records
    extracted     = [r for r in records if r["strip"] == 0]
    extracted_ids = {r["cid"] for r in extracted}
    actual_fraud  = [r for r in records if r["is_fraud"]]
    tp = len([r for r in actual_fraud  if r["cid"] in extracted_ids])
    fp = len([r for r in records if not r["is_fraud"] and r["cid"] in extracted_ids])

    # Sample: first 30 by sboeid, showing is_fraud
    sample = sorted(records, key=lambda r: r["sboeid"])[:30]

    return jsonify({
        "total":        len(records),
        "n_legit":      len(legit_cids),
        "n_fraud":      len(fraud_cids),
        "extracted":    len(extracted),
        "true_pos":     tp,
        "false_pos":    fp,
        "fraud_pct":    round(100 * len(actual_fraud) / len(records), 1),
        "sample":       sample,
    })


@app.route("/api/states")
def api_states():
    return jsonify(STATE_DATA)


@app.route("/api/tartan", methods=["POST"])
def api_tartan():
    """Simulate Tartan OOR partition column/slab structure."""
    data         = request.get_json(silent=True) or {}
    n            = min(int(data.get("n", 400)), 1000)
    pct_slab     = float(data.get("pct_slab", 0.30))
    seed         = int(data.get("seed", 7))
    random.seed(seed)

    OOR_HIGH_MIN = 40_481_162
    cutoff       = date(2007, 6, 1)

    records = []
    n_slab  = int(n * pct_slab)

    for i in range(n):
        is_slab      = i < n_slab
        formation    = "slab" if is_slab else "column"
        county       = random.randint(1, 62)
        cid          = random.randint(10000, 999999)
        pre_cutoff   = random.random() < 0.80
        start        = date(1950,1,1) if pre_cutoff else cutoff
        end          = cutoff         if pre_cutoff else date(2021,10,21)
        regdate      = start + timedelta(days=random.randint(0,(end-start).days))

        if formation == "slab":
            sboeid = OOR_HIGH_MIN + (county % 8)*2_000_000 + cid % 50_000
            purge_p = 0.999 if pre_cutoff else 0.50
        else:
            sboeid = OOR_HIGH_MIN + (county*500_000 + cid*1117) % (59_518_837)
            purge_p = 0.424 if pre_cutoff else 0.202

        status   = "Purged" if random.random() < purge_p else "Active"
        is_clone = random.random() < (0.27 if is_slab and pre_cutoff else 0.05)

        records.append({
            "sboeid":     sboeid,
            "cid":        cid,
            "formation":  formation,
            "status":     status,
            "is_clone":   is_clone,
            "pre_cutoff": pre_cutoff,
            "county":     county,
        })

    slab_recs   = [r for r in records if r["formation"]=="slab"]
    col_recs    = [r for r in records if r["formation"]=="column"]
    slab_purged = sum(1 for r in slab_recs  if r["status"]=="Purged")
    col_purged  = sum(1 for r in col_recs   if r["status"]=="Purged")
    slab_clones = sum(1 for r in slab_recs  if r["is_clone"])

    # Scatterplot sample (200 pts)
    sample = random.sample(records, min(200, len(records)))

    return jsonify({
        "total":          n,
        "n_slab":         len(slab_recs),
        "n_column":       len(col_recs),
        "slab_purge_pct": round(100*slab_purged/max(len(slab_recs),1),1),
        "col_purge_pct":  round(100*col_purged/max(len(col_recs),1),1),
        "slab_clone_pct": round(100*slab_clones/max(len(slab_recs),1),1),
        "scatter":        sample,
    })


if __name__ == "__main__":
    app.run(debug=True)
