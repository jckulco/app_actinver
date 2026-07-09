"""
Mapeo del archivo limpio de vulnerabilidades (clean_engine.CleanResult.clean_df)
al modelo de datos de IBM OpenPages, en formato de payloads JSON listos para
POST a /openpages/api/v2/contents (mismo patrón que ejemplo_carga.py).

ACTUALIZADO — esquema real confirmado contra la instancia OpenPages 9.2
(na4.services.cloud.techzone.ibm.com), vía Object Types export + API /types:

  - Vulnerability (name tecnico "Vulnerability", type_definition_id=127) tiene
    tres grupos de campos coexistiendo: Demo-Vulner:*, External System -
    Application Vulnerability:*, OPSS-Vuln:*. Los dos primeros SI estan
    poblados con datos reales en esta instancia y se usan aqui. OPSS-Vuln
    no se vio poblado, se deja fuera por ahora.
  - El objeto padre real de Vulnerability es "Asset2" — name tecnico real
    es "Asset" pero label/plural son "Asset2"/"Assets2" (type_definition_id
    =136). NO es el objeto "Asset" plano (Criticality/Resource Type/etc.)
    que se exporto primero por FastMap — ese es un tipo distinto sin
    relacion directa con Vulnerability.
  - "Tenable" ya fue agregado como valor valido del enum
    Demo-Vulner:Scanning Vendor en esta instancia (confirmado).
  - Severidad: External System - Application Vulnerability:Severity solo
    acepta High/Medium/Low (confirmado por API) -> SEVERITY_MAP colapsa
    Critical->High e Info->Low, que es correcto para ese campo.

CORREGIDO EN ESTA SESION — DESCUBRIMIENTO DE FONDO: todas las correcciones
de formato de sesiones anteriores (camelCase, fields envuelto en
{"field": [...]}, enumValue/multiEnumValue) se basaron en el PDF "GRC REST
API V1 Reference Guide". Pero BASE_URL apunta a /openpages/api/v2 -- la API
V2, que tiene un esquema de payload DISTINTO. Confirmado contra la
especificacion OpenAPI oficial de IBM para v2 9.1
(ejemplo real de POST /v2/contents):

    {
      "fields": [
        {"id": "141", "name": "OPLC-Std:LCComment", "value": "Object comment"},
        {"name": "OPSS-Iss:Identified By Group",
         "value": [{"name": "Internal Audit"}, {"id": "3484"}]},
        {"name": "OPSS-Iss:Status", "value": {"name": "Open"}}
      ],
      "type_definition_id": "6",
      "name": "TestObjectCreate",
      "description": "Test GRC Object create V2"
    }

En la V2 real:
  - Las claves raiz van en snake_case: "type_definition_id",
    "primary_parent_id" (NO camelCase como asumimos antes).
  - "fields" es un ARRAY PLANO, NO un objeto envuelto en {"field": [...]}.
  - No existe "dataType"/"data_type" en el payload de creacion -- la API
    resuelve el tipo de dato del campo por su nombre/id. Cada field es
    simplemente {"name": ..., "value": ...} (o {"id": ..., "value": ...}).
  - No existen las claves "enumValue"/"multiEnumValue". TODO usa una unica
    clave "value":
      - Un solo valor enum:      "value": {"name": "Medium"}
      - Multiples valores enum:  "value": [{"name": "Medium"}, ...]
      - Cualquier otro tipo:     "value": <el valor plano>
  - "typeDefinitionId cannot be null" / "systemName cannot be null" que
    vimos en corridas anteriores eran sintomas de este desajuste de
    esquema (V1 vs V2), no de otro bug adicional.

Sigue pendiente antes de una carga real:
  - Confirmar type_definition_id vigente vía get_all_types() en el momento
    de la carga (no hardcodear un ID viejo si la instancia se reconstruye).
  - Validar con GRC si prefieren usar Demo-Vulner:Severity Rating (escala
    1-5, mapea 1:1 con los 5 niveles de Tenable) en vez de/ademas de
    External System:Severity (3 niveles).
  - Construir la tabla de correspondencia asset_id_canonical -> ID real de
    Asset2 en OpenPages (sigue usando el mismo mecanismo de
    _pending_asset_lookup / _asset_id_canonical de antes -- estos dos
    siguen siendo campos auxiliares NUESTROS que load_to_openpages.py debe
    remover del payload antes del POST; no son parte del esquema de la API).

Uso:
    from openpages_mapper import build_vulnerability_payloads, build_asset_payloads

    vuln_payloads = build_vulnerability_payloads(clean_df)
    asset_payloads = build_asset_payloads(clean_df)
"""
import json
import pandas as pd

# ---------------------------------------------------------------------------
# CONSTANTES EDITABLES
# ---------------------------------------------------------------------------

TYPE_NAME_VULNERABILITY = "Vulnerability"
TYPE_NAME_ASSET = "Asset"  # name tecnico real; label en la UI es "Asset2"

# Campo -> nombre de campo real en OpenPages (Vulnerability)
FIELD_MAP_VULNERABILITY = {
    # Base
    "name": "Name",
    "description": "Description",
    # Demo-Vulner (seccion "Assessment" en la UI)
    "cve": "Demo-Vulner:CVE ID",
    "risk_rating": "Demo-Vulner:Risk Rating",              # ENUM: Warning, Low, Medium, High
    "severity_rating_1_5": "Demo-Vulner:Severity Rating",   # ENUM: '1'..'5'
    "status_demo": "Demo-Vulner:Status",                    # ENUM: Open, Closed
    "type": "Demo-Vulner:Type",                             # ENUM: Hardware, Software, Personnel, Network, Site, Organization
    "scanning_vendor": "Demo-Vulner:Scanning Vendor",       # ENUM: AppScan, McAfee, Qualys, Tenable
    "assessment_method": "Demo-Vulner:Assessment Method",
    "qid": "Demo-Vulner:QID",
    # External System - Application Vulnerability (seccion "Vulnerability Scan Details")
    "port": "External System - Application Vulnerability:Port",
    "domain_or_host": "External System - Application Vulnerability:Domain",
    "severity_multi_enum": "External System - Application Vulnerability:Severity",  # High/Medium/Low
    "status": "External System - Application Vulnerability:Status",
    "scan_output": "External System - Application Vulnerability:Issue Type",
    "path": "External System - Application Vulnerability:Path",
}

# Valores validos por campo ENUM, para validar antes de mandar el POST real.
VULNERABILITY_ENUM_VALUES = {
    "Demo-Vulner:Risk Rating": ["Warning", "Low", "Medium", "High"],
    "Demo-Vulner:Severity Rating": ["1", "2", "3", "4", "5"],
    "Demo-Vulner:Status": ["Open", "Closed"],
    "Demo-Vulner:Type": ["Hardware", "Software", "Personnel", "Network", "Site", "Organization"],
    "Demo-Vulner:Scanning Vendor": ["AppScan", "McAfee", "Qualys", "Tenable"],
    "External System - Application Vulnerability:Severity": ["High", "Medium", "Low"],
    "External System - Application Vulnerability:Status": [
        "New", "Open", "In Progress", "In Review", "Noise", "Past", "Fixed", "Close",
    ],
}

# Campo -> nombre de campo real en OpenPages (Asset2 / name tecnico "Asset")
FIELD_MAP_ASSET = {
    "host_name": "Name",
    "ipv4": "Demo-Asset:IP Address",
    "operating_system": "Demo-Asset:Operating System",
    "tags": "Demo-Asset:Tags",
    "asset_type": "Demo-Asset:Asset Type",           # ENUM: Desktops, Servers, Networks
    "confidentiality": "Demo-Asset:Confidentiality", # ENUM: High, Medium, Low
    "managed_state": "Demo-Asset:Managed State",     # ENUM: Managed, Unmanaged
}

ASSET_ENUM_VALUES = {
    "Demo-Asset:Asset Type": ["Desktops", "Servers", "Networks"],
    "Demo-Asset:Confidentiality": ["High", "Medium", "Low"],
    "Demo-Asset:Managed State": ["Managed", "Unmanaged"],
}

# Campos que en nuestro mapeo son ENUM_TYPE de un solo valor (para saber
# como formar "value": {"name": ...} en vez de un valor plano).
_SINGLE_ENUM_FIELDS = {
    "Demo-Vulner:Risk Rating",
    "Demo-Vulner:Status",
    "Demo-Vulner:Type",
    "Demo-Vulner:Scanning Vendor",
    "External System - Application Vulnerability:Status",
    "Demo-Asset:Asset Type",
    "Demo-Asset:Confidentiality",
    "Demo-Asset:Managed State",
}

# Campos que en nuestro mapeo son MULTI_VALUE_ENUM (para saber como formar
# "value": [{"name": ...}, ...] en vez de un valor plano o un solo dict).
_MULTI_ENUM_FIELDS = {
    "External System - Application Vulnerability:Severity",
}

# type_definition_id conocidos de esta instancia (verificar de nuevo con
# get_all_types() antes de una carga real — pueden cambiar si la instancia
# se reconstruye).
KNOWN_TYPE_IDS = {
    TYPE_NAME_VULNERABILITY: "127",
    TYPE_NAME_ASSET: "136",
}

# Tenable (5 niveles) -> External System:Severity (3 niveles, confirmado
# contra el enum real de esta instancia).
SEVERITY_MAP = {
    "Critical": "High",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
    "Info": "Low",
}

# Tenable (5 niveles) -> Demo-Vulner:Severity Rating (escala 1-5, alternativa
# sin perdida de granularidad; usar si GRC prefiere esta escala).
SEVERITY_RATING_MAP = {
    "Critical": "5",
    "High": "4",
    "Medium": "3",
    "Low": "2",
    "Info": "1",
}


def _field(name, value):
    """Construye un elemento de campo en el formato REAL de la API v2:
    simplemente {"name": ..., "value": ...}. No existe "dataType" ni
    "enumValue"/"multiEnumValue" en el payload de creacion/actualizacion --
    la API resuelve el tipo internamente por el nombre/id del campo.

    El llamador es responsable de darle a `value` la forma correcta segun
    el tipo del campo (ver _enum_value / _multi_enum_value)."""
    return {"name": name, "value": value}


def _plain_or_enum_value(field_name, raw_value):
    """Dado el nombre TECNICO real del campo (p.ej. 'Demo-Vulner:Risk
    Rating') y un valor 'crudo' (string simple), devuelve el `value` con
    la forma que esa API v2 espera para ese campo:
      - Si el campo es un ENUM_TYPE de un solo valor (ver
        _SINGLE_ENUM_FIELDS): {"name": raw_value}
      - Si el campo es MULTI_VALUE_ENUM (ver _MULTI_ENUM_FIELDS):
        [{"name": raw_value}]
      - En cualquier otro caso: raw_value tal cual (string, int, etc.)
    """
    if field_name in _SINGLE_ENUM_FIELDS:
        return {"name": raw_value}
    if field_name in _MULTI_ENUM_FIELDS:
        return [{"name": raw_value}]
    return raw_value


def _severity_openpages(tenable_severity):
    return SEVERITY_MAP.get(str(tenable_severity), "Low")


def _severity_rating_openpages(tenable_severity):
    return SEVERITY_RATING_MAP.get(str(tenable_severity), "1")


def build_vulnerability_payloads(clean_df: pd.DataFrame) -> list:
    """Construye un payload por fila del Excel limpio, listo para
    POST /openpages/api/v2/contents (con type_definition_id y
    primary_parent_id a resolver en tiempo de ejecución).

    NOTA: "_pending_asset_lookup" es un campo AUXILIAR nuestro (no de la
    API) que load_to_openpages.py usa para resolver primary_parent_id y
    luego debe eliminar del payload antes de hacer el POST real."""
    fm = FIELD_MAP_VULNERABILITY
    payloads = []
    for _, row in clean_df.iterrows():
        vuln_name = f"VUL_{row['asset_id_canonical']}_{row['port']}"
        severity_op = _severity_openpages(row["severity"])
        field_list = [
            _field(fm["name"], vuln_name),
            _field(fm["description"], str(row["definition.name"])),
            _field(fm["port"], int(row["port"]) if pd.notna(row["port"]) else None),
            _field(
                fm["domain_or_host"],
                str(row["asset.host_name"]) if pd.notna(row["asset.host_name"]) else str(row["asset.ipv4_addresses"]),
            ),
            _field(fm["risk_rating"], _plain_or_enum_value(fm["risk_rating"], severity_op)),
            _field(fm["severity_multi_enum"], _plain_or_enum_value(fm["severity_multi_enum"], severity_op)),
            _field(fm["status"], _plain_or_enum_value(fm["status"], "Open")),
            _field(fm["status_demo"], _plain_or_enum_value(fm["status_demo"], "Open")),
            _field(fm["scan_output"], str(row.get("output", ""))),
            _field(fm["scanning_vendor"], _plain_or_enum_value(fm["scanning_vendor"], "Tenable")),
        ]
        payload = {
            "type_definition_id": None,  # resolver con get_all_types(..., TYPE_NAME_VULNERABILITY)
            "primary_parent_id": None,   # ID del Asset2 en OpenPages — ver _pending_asset_lookup
            "_pending_asset_lookup": row["asset_id_canonical"],
            "name": vuln_name,
            "description": f"Carga automatizada desde Tenable — {row['definition.name']}",
            "fields": field_list,
        }
        payloads.append(payload)
    return payloads


def build_asset_payloads(clean_df: pd.DataFrame) -> list:
    """Construye un payload por activo único (asset_id_canonical) para el
    objeto Asset2 (name técnico "Asset", ver FIELD_MAP_ASSET).
    primary_parent_id no aplica aquí (es el objeto padre); se usa
    asset_id_canonical como clave de negocio temporal hasta tener la tabla
    de correspondencia con el ID real de OpenPages.

    NOTA: "_asset_id_canonical" es un campo AUXILIAR nuestro (no de la
    API) que load_to_openpages.py usa para construir la tabla de
    correspondencia y luego debe eliminar del payload antes del POST."""
    fm = FIELD_MAP_ASSET
    assets = clean_df.drop_duplicates(subset="asset_id_canonical")
    payloads = []
    for _, row in assets.iterrows():
        field_list = [
            _field(fm["host_name"], str(row["asset.host_name"]) if pd.notna(row["asset.host_name"]) else None),
            _field(fm["ipv4"], str(row["asset.ipv4_addresses"])),
            _field(fm["operating_system"], str(row["asset.operating_system"])),
            _field(fm["tags"], str(row.get("asset.tags", ""))),
        ]
        payload = {
            "type_definition_id": None,  # resolver con get_all_types(..., TYPE_NAME_ASSET)
            "_asset_id_canonical": row["asset_id_canonical"],
            "name": str(row["asset.host_name"]) if pd.notna(row["asset.host_name"]) else str(row["asset.ipv4_addresses"]),
            "fields": field_list,
        }
        payloads.append(payload)
    return payloads


def build_openpages_export(clean_df: pd.DataFrame) -> dict:
    """Empaqueta ambos conjuntos de payloads en un solo dict, listo para
    guardar como .json y usar como insumo del script de carga (ver
    ejemplo_carga.py para el patrón de POST real)."""
    return {
        "_notas": (
            "Esquema confirmado contra la especificacion oficial de la API "
            "OpenPages REST V2 9.1: claves raiz en snake_case "
            "(type_definition_id, primary_parent_id), 'fields' como ARRAY "
            "PLANO (no envuelto), y cada campo es simplemente "
            "{'name':..., 'value':...} -- sin 'dataType', sin 'enumValue', "
            "sin 'multiEnumValue'. Para un solo valor enum, value es "
            "{'name': '...'}; para MULTI_VALUE_ENUM, value es una lista "
            "[{'name': '...'}]. Vulnerability id=127, Asset2 (name tecnico "
            "'Asset') id=136 -- verificar con get_all_types() antes de "
            "cargar por si la instancia cambio."
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
