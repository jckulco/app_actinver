"""
Mapeo del archivo limpio de vulnerabilidades (clean_engine.CleanResult.clean_df)
al modelo de datos de IBM OpenPages, en formato de payloads JSON listos para
POST a /openpages/api/v2/contents (mismo patrón que ejemplo_carga.py).

IMPORTANTE — dos objetos, no uno:
  - Vulnerability: los campos observados en objetos.json (categoría con
    prefijo "Demo-Vulner:") corresponden a una categoría de EJEMPLO/DEMO de
    OpenPages, no necesariamente a la categoría personalizada real de
    Actinver. Por eso todos los nombres de campo viven en las constantes
    de abajo (FIELD_MAP_VULNERABILITY) — un solo lugar para actualizar
    cuando se confirme el esquema real de producción.
  - Asset/System: host_name / ipv4 / operating_system NO son campos de
    Vulnerability, viven en el objeto Asset/System, relacionado vía
    "primary_parent_id". Aún no tenemos el ID real de esos activos en
    OpenPages (pendiente: tabla de correspondencia asset_id_canonical <->
    ID de OpenPages, ver README). Por eso "primary_parent_id" se deja como
    placeholder (None) y se incluye "_pending_asset_lookup" con la clave
    que hay que resolver antes de enviar a la API.

Uso:
    from openpages_mapper import build_vulnerability_payloads, build_asset_payloads

    vuln_payloads = build_vulnerability_payloads(clean_df)
    asset_payloads = build_asset_payloads(clean_df)
"""
import json
import pandas as pd

# ---------------------------------------------------------------------------
# CONSTANTES EDITABLES — ajustar aquí cuando se confirme el esquema real de
# producción de Actinver (vía plantilla FastMap o un query de objetos.json
# contra el ambiente productivo, no el de demo).
# ---------------------------------------------------------------------------

TYPE_NAME_VULNERABILITY = "Vulnerability"
TYPE_NAME_ASSET = "Asset/System"

# Campo -> nombre de campo en OpenPages (Vulnerability)
FIELD_MAP_VULNERABILITY = {
    "name": "Name",
    "description": "Description",
    "cve": "Demo-Vulner:CVE ID",
    "risk_rating": "Demo-Vulner:Risk Rating",
    "port": "External System - Application Vulnerability:Port",
    "domain_or_host": "External System - Application Vulnerability:Domain",
    "severity_multi_enum": "External System - Application Vulnerability:Severity",
    "status": "External System - Application Vulnerability:Status",
    "scan_output": "External System - Application Vulnerability:Issue Type",
}

# Campo -> nombre de campo en OpenPages (Asset/System) — NOMBRES PROVISIONALES,
# no confirmados contra el esquema real (no tenemos aún la plantilla FastMap
# de Asset/System). Ajustar en cuanto se reciba.
FIELD_MAP_ASSET = {
    "host_name": "Name",
    "ipv4": "IPv4 Address",
    "operating_system": "Operating System",
    "tags": "Tags",
}

# Tenable (5 niveles) -> OpenPages Risk/Severity (3 niveles observados: High/Medium/Low)
SEVERITY_MAP = {
    "Critical": "High",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Low",
}


def _field(name, data_type, value):
    return {"name": name, "data_type": data_type, "value": value}


def _severity_openpages(tenable_severity):
    return SEVERITY_MAP.get(str(tenable_severity), "Low")


def build_vulnerability_payloads(clean_df: pd.DataFrame) -> list:
    """Construye un payload por fila del Excel limpio, listo para
    POST /openpages/api/v2/contents (con type_definition_id y
    primary_parent_id a resolver en tiempo de ejecución)."""
    fm = FIELD_MAP_VULNERABILITY
    payloads = []
    for _, row in clean_df.iterrows():
        vuln_name = f"VUL_{row['asset_id_canonical']}_{row['port']}"
        payload = {
            "type_definition_id": None,  # resolver con get_all_types(..., TYPE_NAME_VULNERABILITY)
            "primary_parent_id": None,   # ID del Asset/System en OpenPages — ver _pending_asset_lookup
            "_pending_asset_lookup": row["asset_id_canonical"],
            "name": vuln_name,
            "description": f"Carga automatizada desde Tenable — {row['definition.name']}",
            "fields": [
                _field(fm["name"], "STRING_TYPE", vuln_name),
                _field(fm["description"], "STRING_TYPE", str(row["definition.name"])),
                _field(fm["port"], "INTEGER_TYPE", int(row["port"]) if pd.notna(row["port"]) else None),
                _field(
                    fm["domain_or_host"],
                    "STRING_TYPE",
                    str(row["asset.host_name"]) if pd.notna(row["asset.host_name"]) else str(row["asset.ipv4_addresses"]),
                ),
                _field(fm["risk_rating"], "ENUM_TYPE", {"name": _severity_openpages(row["severity"])}),
                _field(fm["severity_multi_enum"], "MULTI_VALUE_ENUM", {"name": _severity_openpages(row["severity"])}),
                _field(fm["status"], "ENUM_TYPE", {"name": "Open"}),
                _field(fm["scan_output"], "STRING_TYPE", str(row.get("output", ""))),
            ],
        }
        payloads.append(payload)
    return payloads


def build_asset_payloads(clean_df: pd.DataFrame) -> list:
    """Construye un payload por activo único (asset_id_canonical) para el
    objeto Asset/System. Nombres de campo PROVISIONALES (ver FIELD_MAP_ASSET).
    primary_parent_id no aplica aquí (es el objeto padre); se usa
    asset_id_canonical como clave de negocio temporal hasta tener la tabla
    de correspondencia con el ID real de OpenPages."""
    fm = FIELD_MAP_ASSET
    assets = clean_df.drop_duplicates(subset="asset_id_canonical")
    payloads = []
    for _, row in assets.iterrows():
        payload = {
            "type_definition_id": None,  # resolver con get_all_types(..., TYPE_NAME_ASSET)
            "_asset_id_canonical": row["asset_id_canonical"],
            "name": str(row["asset.host_name"]) if pd.notna(row["asset.host_name"]) else str(row["asset.ipv4_addresses"]),
            "fields": [
                _field(fm["host_name"], "STRING_TYPE", str(row["asset.host_name"]) if pd.notna(row["asset.host_name"]) else None),
                _field(fm["ipv4"], "STRING_TYPE", str(row["asset.ipv4_addresses"])),
                _field(fm["operating_system"], "STRING_TYPE", str(row["asset.operating_system"])),
                _field(fm["tags"], "STRING_TYPE", str(row.get("asset.tags", ""))),
            ],
        }
        payloads.append(payload)
    return payloads


def build_openpages_export(clean_df: pd.DataFrame) -> dict:
    """Empaqueta ambos conjuntos de payloads en un solo dict, listo para
    guardar como .json y usar como insumo del script de carga (ver
    ejemplo_carga.py para el patrón de POST real)."""
    return {
        "_notas": (
            "type_definition_id y primary_parent_id vienen en None — se "
            "resuelven en tiempo de ejecucion con get_all_types() y con la "
            "tabla de correspondencia asset_id_canonical -> ID de OpenPages "
            "(pendiente, ver README). Los nombres de campo en "
            "FIELD_MAP_VULNERABILITY / FIELD_MAP_ASSET (openpages_mapper.py) "
            "son provisionales y deben confirmarse contra el esquema real "
            "de produccion de Actinver, no el de demo."
        ),
        "assets": build_asset_payloads(clean_df),
        "vulnerabilities": build_vulnerability_payloads(clean_df),
    }


if __name__ == "__main__":
    import sys
    from clean_engine import clean_tenable_export

    vuln_path = sys.argv[1] if len(sys.argv) > 1 else "Vul_IBM.xlsx"
    joyas_path = sys.argv[2] if len(sys.argv) > 2 else None
    result = clean_tenable_export(vuln_path, joyas_path)
    export = build_openpages_export(result.clean_df)
    print(json.dumps(export, indent=2, default=str)[:2000])
