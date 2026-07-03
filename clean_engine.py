"""
Motor de limpieza para exports de vulnerabilidades de Tenable.
Resuelve el problema de activos duplicados por inconsistencia en asset.operating_system.

Uso:
    from clean_engine import clean_tenable_export
    result = clean_tenable_export('Vul_IBM.xlsx')
    result.clean_df       -> DataFrame limpio, listo para ingesta (ej. OpenPages)
    result.audit_df       -> Detalle de qué filas se fusionaron y por qué
    result.insights       -> dict con métricas para el panel de la app
"""
import re
import hashlib
from dataclasses import dataclass, field
import pandas as pd


def normalize_hostname(name):
    if pd.isna(name) or not str(name).strip():
        return None
    return str(name).strip().lower()


def canonical_key(host_name, ipv4):
    """Clave estable del activo: hostname normalizado, o IP si no hay hostname.
    Se usa un hash determinístico para que sea consistente entre corridas
    (requisito para no duplicar activos en re-ingestas a OpenPages)."""
    h = normalize_hostname(host_name)
    ip = str(ipv4).strip() if pd.notna(ipv4) and str(ipv4).strip() else None
    basis = h or ip or "UNKNOWN"
    raw = f"{h or ''}|{ip or ''}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"AST-{digest}", basis


def os_specificity(os_string):
    """Heurística de qué tan específico es un valor de SO: más largo y con
    más tokens alfanuméricos (build numbers, versiones) = más específico."""
    if pd.isna(os_string):
        return -1
    s = str(os_string)
    build_bonus = 5 if re.search(r"\d{3,}", s) else 0
    return len(s) + build_bonus


SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


@dataclass
class CleanResult:
    clean_df: pd.DataFrame
    audit_df: pd.DataFrame
    insights: dict = field(default_factory=dict)


def clean_tenable_export(path_or_df):
    df = pd.read_excel(path_or_df) if isinstance(path_or_df, str) else path_or_df.copy()

    original_rows = len(df)

    keys = df.apply(
        lambda r: canonical_key(r.get("asset.host_name"), r.get("asset.ipv4_addresses")),
        axis=1,
    )
    df["_asset_key"] = [k[0] for k in keys]
    df["_asset_basis"] = [k[1] for k in keys]
    df["_os_specificity"] = df["asset.operating_system"].apply(os_specificity)
    df["_sev_rank"] = df["severity"].map(SEVERITY_ORDER).fillna(-1)

    # 1) Resolver el SO canónico por activo (el más específico; empate -> last_seen más reciente)
    def pick_os(group):
        g = group.sort_values(
            by=["_os_specificity", "last_seen"], ascending=[False, False]
        )
        return g.iloc[0]["asset.operating_system"]

    os_by_asset = df.groupby("_asset_key").apply(pick_os)
    df["_os_canonical"] = df["_asset_key"].map(os_by_asset)

    variants_by_asset = df.groupby("_asset_key")["asset.operating_system"].apply(
        lambda s: sorted(set(s.dropna().astype(str)))
    )

    # 2) Deduplicar vulnerabilidades: misma vulnerabilidad = mismo activo + definition.name + port
    dedup_key_cols = ["_asset_key", "definition.name", "port"]
    df["_vuln_key"] = df[dedup_key_cols].astype(str).agg("|".join, axis=1)

    df_sorted = df.sort_values(by=["_vuln_key", "_sev_rank", "last_seen"], ascending=[True, False, False])
    keep_mask = ~df_sorted.duplicated(subset="_vuln_key", keep="first")
    clean = df_sorted[keep_mask].copy()
    dropped = df_sorted[~keep_mask].copy()

    clean["asset.operating_system"] = clean["_asset_key"].map(os_by_asset)
    clean["asset_id_canonical"] = clean["_asset_key"]
    clean["os_variants_seen"] = clean["_asset_key"].map(
        lambda k: "; ".join(variants_by_asset.get(k, []))
    )
    clean["merged_duplicate_count"] = clean["_vuln_key"].map(df["_vuln_key"].value_counts()) - 1

    output_cols = [
        "asset_id_canonical", "asset.host_name", "asset.ipv4_addresses",
        "asset.operating_system", "os_variants_seen", "port", "output",
        "definition.name", "severity", "last_seen", "merged_duplicate_count",
    ]
    clean_out = clean[output_cols].sort_values(
        by=["asset.host_name", "definition.name"]
    ).reset_index(drop=True)

    # 3) Construir hoja de auditoría: qué filas originales se colapsaron en cuál fila final
    audit_rows = []
    for vuln_key, group in df_sorted.groupby("_vuln_key"):
        if len(group) <= 1:
            continue
        kept = group.iloc[0]
        for _, r in group.iterrows():
            audit_rows.append({
                "asset_id_canonical": r["_asset_key"],
                "host_name": r["asset.host_name"],
                "ipv4": r["asset.ipv4_addresses"],
                "definition.name": r["definition.name"],
                "port": r["port"],
                "os_en_esta_fila": r["asset.operating_system"],
                "severity_en_esta_fila": r["severity"],
                "last_seen": r["last_seen"],
                "conservada": r.name == kept.name,
                "os_canonico_asignado": r["_os_canonical"],
            })
    audit_df = pd.DataFrame(audit_rows)

    insights = {
        "filas_originales": original_rows,
        "filas_limpias": len(clean_out),
        "filas_eliminadas_por_duplicado": original_rows - len(clean_out),
        "pct_reduccion": round((original_rows - len(clean_out)) / original_rows * 100, 1) if original_rows else 0,
        "activos_unicos": df["_asset_key"].nunique(),
        "activos_con_multiples_os_registrados": int((variants_by_asset.apply(len) > 1).sum()),
        "severidad_criticas_conservadas": int((clean_out["severity"] == "Critical").sum()),
        "severidad_altas_conservadas": int((clean_out["severity"] == "High").sum()),
    }

    return CleanResult(clean_df=clean_out, audit_df=audit_df, insights=insights)


if __name__ == "__main__":
    import sys
    result = clean_tenable_export(sys.argv[1] if len(sys.argv) > 1 else "Vul_IBM.xlsx")
    print(result.insights)
