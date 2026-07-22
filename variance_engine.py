"""
Variance 360 engine — column composition + stage variance profiling.

Mapping source : legacy_lineage  (stage chain per field, per data_source)
Formats/PII    : legacy_dictionary (DATE_FORMAT masks, IS_PII sample suppression)
Results        : recon_runs / recon_dtype_profile / recon_profile / recon_summary
                 written to the CP Catalog (SILVER) database via app.db pool.

Source connections (where the actual stage tables live) come from env:
    CP_VAR_<DS>_DSN        e.g. CP_VAR_PBDW_DSN=user:pwd@host:1521/pbdw
    CP_VAR_<DS>_SCHEMA_SRC / _STG1 / _STG2 / _DWH
                           optional schema prefixes per stage; if a stage table
                           in legacy_lineage is unqualified, this prefix is used.
If CP_VAR_<DS>_DSN is unset the engine profiles through the SILVER connection
(assumes synonyms / same instance).

Requires Oracle >= 12.2 on the profiled source (VALIDATE_CONVERSION).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import re
from collections import defaultdict

log = logging.getLogger("cp.variance.engine")

# metric severity weights for the variance score
_WEIGHT = {"CNT": 3, "SUM": 3, "HASHSUM": 2}
_NUM_TOL = 1e-4          # relative tolerance for SUM/AVG comparisons
_BATCH = 30              # columns per generated probe query
_SAMPLES = 5             # outlier samples per risky column
_STAGES = ["SRC", "STG1", "STG2", "DWH"]
_DEFAULT_MASKS = ["YYYYMMDD", "YYYY-MM-DD", "MM/DD/YYYY",
                  "YYYY-MM-DD HH24:MI:SS", "DD-MON-YYYY"]

_IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_$#]*(\.[A-Za-z][A-Za-z0-9_$#]*)?$")


def _is_db_object(name):
    """SRC entries in legacy_lineage can be flat-file names
    (e.g. 'Addv-MSTR-ACC-...YYYYMMDDHHMMSS.dat') — not probeable via SQL."""
    return bool(name) and bool(_IDENT.match(str(name).strip()))


def _oracle_mask(mask):
    """Translate Java/informal date masks from legacy_dictionary into valid
    Oracle format masks; return None when the result is still unusable
    (e.g. a format code would appear twice -> ORA-01810)."""
    if not mask:
        return None
    m = str(mask).strip().upper()
    m = (m.replace("HH24", "H24_")            # protect an already-valid HH24
           .replace("HHMMSS", "HH24MISS")
           .replace("HH:MM:SS", "HH24:MI:SS")
           .replace("HH.MM.SS", "HH24.MI.SS")
           .replace("H24_", "HH24"))
    m = re.sub(r"(?<!H)MM(?=SS)", "MI", m)     # ...MMSS -> ...MISS
    m = m.replace("SSSSSS", "SS")              # FF* is illegal for DATE input
    if len(re.findall(r"MM", m)) > 1:          # month + minutes both as MM
        return None
    # tokenize and keep only DATE-input-legal codes (ORA-01820 guard)
    token_re = re.compile(
        r"YYYY|RRRR|YY|MON|MM|DD|HH24|HH12|HH|MI|SS|AM|PM|[:/\-\. ]")
    pos, out = 0, []
    while pos < len(m):
        t = token_re.match(m, pos)
        if not t:
            return None                        # unknown token (FF, DY, TZ...)
        out.append(t.group(0))
        pos = t.end()
    return "".join(out)


# --------------------------------------------------------------------------
# connections
# --------------------------------------------------------------------------
def _parse_dsn(dsn: str):
    """'user:pwd@host:1521/service' -> (user, pwd, 'host:1521/service')."""
    cred, _, hostpart = dsn.rpartition("@")
    user, _, pwd = cred.partition(":")
    if not user or not hostpart:
        raise ValueError(
            "DSN must look like user:password@host:port/service")
    return user, pwd, hostpart


_thick_ready = False


def _init_driver():
    """Servers requiring Native Network Encryption (DPY-3001) need thick
    mode. Set CP_ORACLE_CLIENT_DIR to the Oracle Client / Instant Client
    directory (the one containing oci.dll on Windows) to enable it."""
    global _thick_ready
    if _thick_ready:
        return
    import oracledb
    lib = os.environ.get("CP_ORACLE_CLIENT_DIR")
    if lib:
        oracledb.init_oracle_client(lib_dir=lib)
    _thick_ready = True


def _verify_masks(scur, masks):
    """Test-fire each mask against dual; drop any the DB rejects
    (definitive guard against ORA-01810/01820/01821 family)."""
    ok = []
    for m in masks:
        try:
            scur.execute(
                f"SELECT VALIDATE_CONVERSION('1' AS DATE, '{m}') FROM dual")
            scur.fetchone()
            ok.append(m)
        except Exception as e:                              # noqa: BLE001
            log.warning("mask dropped (%s): %s", m, str(e)[:80])
    return ok or list(_DEFAULT_MASKS[:3])


def _connect(dsn: str):
    import oracledb
    _init_driver()
    user, pwd, hostpart = _parse_dsn(dsn)
    return oracledb.connect(user=user, password=pwd, dsn=hostpart)


def _catalog():
    """Connection to the CP Catalog DB (SILVER).
    Prefers CP_CATALOG_DB_DSN env; falls back to the API pool when the
    engine runs inside the API process."""
    dsn = os.environ.get("CP_CATALOG_DB_DSN")
    if dsn:
        return _connect(dsn)
    try:                                    # running inside the API package
        from app.db import get_pool         # type: ignore
        return get_pool().acquire()
    except ImportError:
        try:
            from api.app.db import get_pool  # type: ignore  # repo-root run
            return get_pool().acquire()
        except ImportError as e:
            raise RuntimeError(
                "Set CP_CATALOG_DB_DSN (user:pwd@host:port/service) — "
                "the API package is not importable from here.") from e


def _source_conn(data_source: str):
    """Connection to the warehouse being profiled; falls back to catalog."""
    dsn = os.environ.get(f"CP_VAR_{data_source.upper()}_DSN")
    if not dsn:
        return _catalog(), False
    return _connect(dsn), True


def _stage_schema(data_source: str, stage: str) -> str | None:
    return os.environ.get(f"CP_VAR_{data_source.upper()}_SCHEMA_{stage}")


def _qual(data_source: str, stage: str, table: str) -> str:
    if not table:
        return table
    if "." in table:
        return table
    sch = _stage_schema(data_source, stage)
    return f"{sch}.{table}" if sch else table


# --------------------------------------------------------------------------
# mapping: read chains from legacy_lineage (+ dictionary enrichment)
# --------------------------------------------------------------------------
def load_chains(cur, data_source: str, table: str | None):
    """One dict per mapped field: per-stage (table, column, declared_type)."""
    sql = """
        SELECT lineage_id, functional_group,
               src_source_table,  src_source_column,
               stg1_source_table, stg1_source_column, stg1_type,
               stg2_source_table, stg2_source_column, stg2_type,
               dwh_target_table,  dwh_target_column,  dwh_type,
               NVL(lineage_status, 'unmapped') AS lineage_status
        FROM legacy_lineage
        WHERE NVL(data_source, 'PBDW') = :ds
          AND LOWER(NVL(lineage_status, 'x')) IN ('mapped', 'exists')
    """
    binds = {"ds": data_source}
    if table:
        sql += " AND UPPER(dwh_target_table) = UPPER(:t)"
        binds["t"] = table
    cur.execute(sql, binds)
    cols = [d[0].lower() for d in cur.description]
    chains = []
    for row in cur.fetchall():
        r = dict(zip(cols, row))
        chains.append({
            "lineage_id": r["lineage_id"],
            "fgroup": r["functional_group"],
            "SRC":  (r["src_source_table"],  r["src_source_column"],  None),
            "STG1": (r["stg1_source_table"], r["stg1_source_column"], r["stg1_type"]),
            "STG2": (r["stg2_source_table"], r["stg2_source_column"], r["stg2_type"]),
            "DWH":  (r["dwh_target_table"],  r["dwh_target_column"],  r["dwh_type"]),
        })
    return chains


def load_dictionary(cur):
    """PB field -> (date_format, is_pii). Join key: PB_FIELD_MAPPING.
    -- EDIT: adjust the join key if your dictionary maps to lineage differently."""
    cur.execute("""
        SELECT UPPER(NVL(pb_field_mapping, field_code_norm)) AS k,
               date_format, NVL(is_pii, 'N') AS is_pii
        FROM legacy_dictionary""")
    out = {}
    for k, mask, pii in cur.fetchall():
        if k:
            out[k] = (mask, pii == "Y")
    return out


# --------------------------------------------------------------------------
# composition probes (content-type census)
# --------------------------------------------------------------------------
def _probe_exprs(col: str, masks: list[str]):
    c = f'"{col.upper()}"'
    v = f"TRIM({c})"
    num = f"VALIDATE_CONVERSION({v} AS NUMBER)"
    e = {
        "TOTAL":   "COUNT(*)",
        "NONNULL": f"COUNT({v})",
        "NUM_OK":  f"SUM(CASE WHEN {v} IS NOT NULL THEN {num} ELSE 0 END)",
        "INT_OK":  (f"SUM(CASE WHEN {v} IS NOT NULL AND {num}=1 "
                    f"AND INSTR({v},'.')=0 THEN 1 ELSE 0 END)"),
        "PRECMAX": (f"MAX(CASE WHEN {v} IS NOT NULL AND {num}=1 THEN "
                    f"LENGTH(REPLACE(REPLACE(REPLACE({v},'-'),'+'),'.')) END)"),
        "SCALEMAX": (f"MAX(CASE WHEN {v} IS NOT NULL AND {num}=1 AND INSTR({v},'.')>0 "
                     f"THEN LENGTH(SUBSTR({v}, INSTR({v},'.')+1)) ELSE 0 END)"),
        "LEADZERO": (f"SUM(CASE WHEN {v} IS NOT NULL AND {num}=1 AND LENGTH({v})>1 "
                     f"AND SUBSTR({v},1,1)='0' AND INSTR({v},'.')<>2 "
                     f"THEN 1 ELSE 0 END)"),
        "BOOL_OK": (f"SUM(CASE WHEN UPPER({v}) IN ('Y','N','T','F','0','1') "
                    f"THEN 1 ELSE 0 END)"),
        "MAXLEN":  f"MAX(LENGTH({v}))",
    }
    for i, m in enumerate(masks):
        e[f"DT{i}"] = (f"SUM(CASE WHEN {v} IS NOT NULL THEN "
                       f"VALIDATE_CONVERSION({v} AS DATE, '{m}') ELSE 0 END)")
    return e


def _classify(s: dict, masks: list[str]):
    nn = s.get("NONNULL") or 0
    total = s.get("TOTAL") or 0
    if nn == 0:
        return "EMPTY", 100.0, {}, ""
    p = lambda k: 100.0 * (s.get(k) or 0) / nn
    pcts = {
        "decimal": p("NUM_OK") - p("INT_OK"),
        "integer": p("INT_OK"),
        "bool": p("BOOL_OK"),
        "blank": 100.0 * (total - nn) / total if total else 0.0,
    }
    best_date, best_mask = 0.0, None
    for i, m in enumerate(masks):
        if p(f"DT{i}") > best_date:
            best_date, best_mask = p(f"DT{i}"), m
    pcts["date"] = best_date

    THR = 98.0
    if pcts["bool"] >= THR and p("NUM_OK") < THR:
        return "BOOLEAN_FLAG", pcts["bool"], pcts, ""
    if best_date >= THR and p("INT_OK") < THR:
        return f"DATE:{best_mask}", best_date, pcts, best_mask
    if p("INT_OK") >= THR:
        if (s.get("LEADZERO") or 0) > 0:
            return "STRING_NUMERICLOOK", 100.0, pcts, ""
        if best_date >= THR:                      # int-vs-YYYYMMDD ambiguity
            return f"DATE:{best_mask}", best_date, pcts, best_mask
        return "INTEGER", p("INT_OK"), pcts, ""
    if p("NUM_OK") >= THR:
        return "DECIMAL", p("NUM_OK"), pcts, ""
    if max(p("NUM_OK"), best_date, pcts["bool"]) > 50:
        return "MIXED", max(p("NUM_OK"), best_date), pcts, best_mask or ""
    return "STRING", 100.0 - max(p("NUM_OK"), best_date), pcts, ""


def _risk_and_verdict(inferred, conf, s, declared):
    bad = ""
    if inferred == "STRING_NUMERICLOOK":
        return ("IDENTIFIER_LEADING_ZERO",
                "NEVER cast to NUMBER — leading zeros would be lost; keep VARCHAR2")
    if inferred.startswith(("INTEGER", "DECIMAL", "DATE", "BOOLEAN")) and conf < 100.0:
        n_bad = round((s.get("NONNULL") or 0) * (100.0 - conf) / 100.0)
        return ("CAST_UNSAFE",
                f"cast fails ~{n_bad:,} rows — cleanse before cast")
    if inferred.startswith(("INTEGER", "DECIMAL")) and "CHAR" in (declared or ""):
        tgt = (f"NUMBER({int(s.get('PRECMAX') or 18)},"
               f"{int(s.get('SCALEMAX') or 0)})")
        return ("TYPE_DRIFT", f"safe cast -> {tgt}")
    if inferred.startswith("DATE") and "CHAR" in (declared or ""):
        return ("TYPE_DRIFT", "safe cast -> DATE")
    return (bad, "genuine string" if inferred == "STRING" else "")


def _fetch_samples(cur, qtable, col, inferred, mask):
    v = f'TRIM("{col.upper()}")'
    if inferred in ("INTEGER", "DECIMAL"):
        cond = f"VALIDATE_CONVERSION({v} AS NUMBER)=0"
    elif inferred.startswith("DATE:"):
        cond = f"VALIDATE_CONVERSION({v} AS DATE, '{mask}')=0"
    else:
        return []
    try:
        cur.execute(f"""SELECT {v} FROM {qtable}
                        WHERE {v} IS NOT NULL AND {cond}
                          AND ROWNUM <= {_SAMPLES}""")
        return [str(r[0])[:80] for r in cur.fetchall()]
    except Exception as e:                                    # noqa: BLE001
        log.warning("sample fetch failed %s.%s: %s", qtable, col, str(e)[:120])
        return []


# --------------------------------------------------------------------------
# stage-variance metrics
# --------------------------------------------------------------------------
def _metric_exprs(col, dclass):
    c = f'"{col.upper()}"'
    base = [("CNT", f"COUNT({c})"),
            ("NULLS", f"SUM(CASE WHEN {c} IS NULL THEN 1 ELSE 0 END)"),
            ("NDV", f"APPROX_COUNT_DISTINCT({c})")]
    if dclass == "NUM":
        return base + [("SUM", f"SUM(TO_NUMBER({c} DEFAULT NULL ON CONVERSION ERROR))"),
                       ("MIN", f"MIN(TO_NUMBER({c} DEFAULT NULL ON CONVERSION ERROR))"),
                       ("MAX", f"MAX(TO_NUMBER({c} DEFAULT NULL ON CONVERSION ERROR))")]
    if dclass == "DATE":
        return base + [("MIN_D", f"TO_CHAR(MIN({c}))"), ("MAX_D", f"TO_CHAR(MAX({c}))")]
    return base + [("MAXLEN", f"MAX(LENGTH(TRIM({c})))"),
                   ("HASHSUM", f"SUM(ORA_HASH(TRIM({c})))")]


def _dclass_from_inferred(inferred: str) -> str:
    if inferred in ("INTEGER", "DECIMAL"):
        return "NUM"
    if inferred.startswith("DATE"):
        return "STR"   # stage tables store as string; compare as string+hash
    return "STR"


# --------------------------------------------------------------------------
# run orchestration
# --------------------------------------------------------------------------
def _upd_run(ccur, cconn, run_id, **kw):
    sets = ", ".join(f"{k} = :{k}" for k in kw)
    ccur.execute(f"UPDATE recon_runs SET {sets} WHERE run_id = :run_id",
                 dict(kw, run_id=run_id))
    cconn.commit()


def run_profile(data_source: str, table: str | None, analysis: str = "BOTH",
                sample_rows: int = 0, run_id: str | None = None) -> str:
    """Entry point (called by the router as a background task)."""
    run_id = run_id or f"V{dt.datetime.now():%Y%m%d_%H%M%S}"
    cconn = _catalog()
    ccur = cconn.cursor()
    ccur.execute("""INSERT INTO recon_runs
        (run_id, data_source, run_type, scope) VALUES (:1, :2, :3, :4)""",
        [run_id, data_source, analysis, table or "ALL"])
    cconn.commit()
    try:
        _upd_run(ccur, cconn, run_id, step="reading legacy_lineage chains")
        chains = load_chains(ccur, data_source, table)
        if not chains:
            raise RuntimeError(f"no mapped chains in legacy_lineage for "
                               f"{data_source}/{table or 'ALL'}")
        dictionary = load_dictionary(ccur)
        masks = list(_DEFAULT_MASKS)
        for raw, _ in dictionary.values():
            m = _oracle_mask(raw)
            if m and m not in masks:
                masks.append(m)
        masks = masks[:8]

        sconn, own = _source_conn(data_source)
        scur = sconn.cursor()
        masks = _verify_masks(scur, masks)
        log.info("date masks in use: %s", masks)
        sql_hasher = hashlib.sha256()
        rows_scanned, cols_done = 0, 0
        inferred_by_key = {}

        # ---- pass 1: composition per stage table -------------------------
        if analysis in ("BOTH", "COMPOSITION"):
            by_table = defaultdict(set)
            skipped_files = set()
            for ch in chains:
                for st in _STAGES:
                    t, c, _ = ch[st]
                    if t and c:
                        if _is_db_object(t):
                            by_table[(st, t)].add(c)
                        else:
                            skipped_files.add(t)
            if skipped_files:
                log.info("%d file-based sources skipped (not SQL-probeable), "
                         "e.g. %s", len(skipped_files),
                         next(iter(skipped_files))[:60])
            n_t = len(by_table)
            for i, ((stage, tab), colset) in enumerate(sorted(by_table.items()), 1):
                _upd_run(ccur, cconn, run_id,
                         step=f"composition {i}/{n_t}: {stage} {tab}")
                qtab = _qual(data_source, stage, tab)
                src = (f"(SELECT * FROM {qtab} WHERE ROWNUM <= {sample_rows})"
                       if sample_rows else qtab)
                cols = sorted(colset)
                for b in range(0, len(cols), _BATCH):
                    batch = cols[b:b + _BATCH]
                    items, manifest = [], []
                    for col in batch:
                        for name, expr in _probe_exprs(col, masks).items():
                            alias = f"P{len(manifest)}"
                            items.append(f"{expr} AS {alias}")
                            manifest.append((col, name))
                    sql = "SELECT " + ", ".join(items) + f" FROM {src}"
                    sql_hasher.update(sql.encode())
                    try:
                        scur.execute(sql)
                        row = scur.fetchone()
                    except Exception as e:                     # noqa: BLE001
                        log.warning("probe failed %s: %s", qtab, str(e)[:160])
                        continue
                    stats = defaultdict(dict)
                    for (col, name), val in zip(manifest, row):
                        stats[col][name] = val
                    for col, s in stats.items():
                        inferred, conf, pcts, mask = _classify(s, masks)
                        risk, verdict = _risk_and_verdict(inferred, conf, s, "")
                        key = f"{tab}.{col}".upper()
                        inferred_by_key[key] = inferred
                        _, is_pii = dictionary.get(col.upper(), (None, False))
                        samples = ([] if is_pii or not risk == "CAST_UNSAFE"
                                   else _fetch_samples(scur, qtab, col, inferred, mask))
                        nn = s.get("NONNULL") or 0
                        bad = round(nn * (100.0 - conf) / 100.0) if conf < 100 else 0
                        ccur.execute("""INSERT INTO recon_dtype_profile
                            (run_id, data_source, stage, table_name, column_name,
                             declared_type, inferred_type, conformance_pct,
                             total_rows, nonnull_rows, pct_decimal, pct_integer,
                             pct_date, pct_bool, pct_blank, pct_bad, bad_rows,
                             num_prec_max, num_scale_max, max_len, lead_zero_rows,
                             date_mask, risk, verdict, samples_json, pii_suppressed)
                            VALUES (:1,:2,:3,:4,:5,:6,:7,:8,:9,:10,:11,:12,:13,
                                    :14,:15,:16,:17,:18,:19,:20,:21,:22,:23,:24,
                                    :25,:26)""",
                            [run_id, data_source, stage, tab, col, None, inferred,
                             round(conf, 2), s.get("TOTAL"), nn,
                             round(pcts.get("decimal", 0), 2),
                             round(pcts.get("integer", 0), 2),
                             round(pcts.get("date", 0), 2),
                             round(pcts.get("bool", 0), 2),
                             round(pcts.get("blank", 0), 2),
                             round(100.0 - conf, 2) if conf < 100 else 0,
                             bad, s.get("PRECMAX"), s.get("SCALEMAX"),
                             s.get("MAXLEN"), s.get("LEADZERO"), mask or None,
                             risk or None, verdict or None,
                             json.dumps(samples) if samples else None,
                             "Y" if is_pii else "N"])
                        cols_done += 1
                    rows_scanned = max(rows_scanned,
                                       stats[batch[0]].get("TOTAL") or 0)
                    cconn.commit()

        # ---- pass 2: stage variance metrics ------------------------------
        if analysis in ("BOTH", "STAGE"):
            per_table = defaultdict(list)   # (stage, table) -> [(chain, col)]
            for ch in chains:
                for st in _STAGES:
                    t, c, _ = ch[st]
                    if t and c and _is_db_object(t):
                        per_table[(st, t)].append((ch, c))
            n_t = len(per_table)
            for i, ((stage, tab), pairs) in enumerate(sorted(per_table.items()), 1):
                _upd_run(ccur, cconn, run_id,
                         step=f"stage metrics {i}/{n_t}: {stage} {tab}")
                qtab = _qual(data_source, stage, tab)
                for b in range(0, len(pairs), _BATCH):
                    batch = pairs[b:b + _BATCH]
                    items, manifest = [], []
                    for ch, col in batch:
                        dclass = _dclass_from_inferred(
                            inferred_by_key.get(f"{tab}.{col}".upper(), "STRING"))
                        for m, expr in _metric_exprs(col, dclass):
                            alias = f"M{len(manifest)}"
                            items.append(f"{expr} AS {alias}")
                            manifest.append((ch, col, m))
                    sql = "SELECT " + ", ".join(items) + f" FROM {qtab}"
                    sql_hasher.update(sql.encode())
                    try:
                        scur.execute(sql)
                        row = scur.fetchone()
                    except Exception as e:                     # noqa: BLE001
                        log.warning("metrics failed %s: %s", qtab, str(e)[:160])
                        continue
                    for (ch, col, m), val in zip(manifest, row):
                        vnum = val if isinstance(val, (int, float)) else None
                        vstr = None if vnum is not None else (
                            str(val)[:200] if val is not None else None)
                        ccur.execute("""INSERT INTO recon_profile
                            (run_id, data_source, lineage_id, stage, table_name,
                             column_name, metric, value_num, value_str)
                            VALUES (:1,:2,:3,:4,:5,:6,:7,:8,:9)""",
                            [run_id, data_source, ch["lineage_id"], stage, tab,
                             col, m, vnum, vstr])
                    cconn.commit()
            _summarize(ccur, cconn, run_id, data_source, chains)

        if own:
            sconn.close()
        _upd_run(ccur, cconn, run_id, status="COMPLETE", step="done",
                 finished_at=dt.datetime.now(), rows_scanned=rows_scanned,
                 cols_profiled=cols_done, sql_hash=sql_hasher.hexdigest()[:16])
    except Exception as e:                                     # noqa: BLE001
        log.exception("variance run failed")
        _upd_run(ccur, cconn, run_id, status="FAILED",
                 error_text=str(e)[:1900], finished_at=dt.datetime.now())
    return run_id


def _summarize(ccur, cconn, run_id, data_source, chains):
    """First-break-hop analysis per field -> recon_summary per table."""
    ccur.execute("""SELECT lineage_id, stage, metric,
                           COALESCE(TO_CHAR(value_num), value_str)
                    FROM recon_profile WHERE run_id = :r""", {"r": run_id})
    vals = defaultdict(dict)
    for lid, stage, metric, v in ccur.fetchall():
        vals[lid][(stage, metric)] = v

    hops = list(zip(_STAGES, _STAGES[1:]))
    tstats = defaultdict(lambda: {"total": 0, "variant": 0, "score": 0.0,
                                  "hop": defaultdict(int),
                                  "metric": defaultdict(int), "fg": None})
    for ch in chains:
        tab = ch["DWH"][0]
        st = tstats[tab]
        st["total"] += 1
        st["fg"] = ch["fgroup"]
        broke = False
        for a, b in hops:
            for metric in ("CNT", "NULLS", "NDV", "SUM", "MAXLEN", "HASHSUM"):
                va = vals[ch["lineage_id"]].get((a, metric))
                vb = vals[ch["lineage_id"]].get((b, metric))
                if va is None or vb is None:
                    continue
                try:
                    fa, fb = float(va), float(vb)
                    diff = abs(fa - fb) / max(abs(fa), abs(fb), 1.0) > _NUM_TOL
                except ValueError:
                    diff = str(va) != str(vb)
                if diff:
                    st["hop"][f"{a}->{b}"] += 1
                    st["metric"][metric] += 1
                    st["score"] += _WEIGHT.get(metric, 1)
                    broke = True
            if broke:
                break
        if broke:
            st["variant"] += 1

    for tab, s in tstats.items():
        score = round(100.0 * s["score"] / max(s["total"], 1), 1)
        worst = max(s["hop"], key=s["hop"].get) if s["hop"] else None
        dom = max(s["metric"], key=s["metric"].get) if s["metric"] else None
        status = ("RED" if score >= 10 or s["metric"].get("CNT")
                  else "AMBER" if score >= 3 else "GREEN")
        ccur.execute("""INSERT INTO recon_summary
            (run_id, data_source, functional_group, table_name, fields_total,
             fields_variant, variance_score, worst_hop, breaks_src_stg1,
             breaks_stg1_stg2, breaks_stg2_dwh, dominant_metric, status)
            VALUES (:1,:2,:3,:4,:5,:6,:7,:8,:9,:10,:11,:12,:13)""",
            [run_id, data_source, s["fg"], tab, s["total"], s["variant"],
             score, worst, s["hop"].get("SRC->STG1", 0),
             s["hop"].get("STG1->STG2", 0), s["hop"].get("STG2->DWH", 0),
             dom, status])
    cconn.commit()
