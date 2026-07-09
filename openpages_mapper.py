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

CORREGIDO EN ESTA SESION (2) — CAUSA RAIZ REAL de "fieldId : null is read
only and cannot be changed.", el mismo error 400 que persistio identico a
traves de TRES formatos de payload distintos (lo cual ya era una pista de
que no era un problema de formato general, sino de un campo puntual mal
incluido). El ejemplo oficial de creacion v2 NUNCA incluye "Name" ni
"Description" dentro del array "fields" -- esos van EXCLUSIVAMENTE como
atributos de nivel superior del payload ("name", "description"). Nuestro
mapeo, en cambio, SIEMPRE agrego ademas un field llamado "Name" (y en
Vulnerability tambien uno llamado "Description"), duplicando el atributo.
"Name"/"Description" son atributos de sistema reservados: cuando se
mandan tambien como field, la API no les puede resolver un fieldId real
(porque no son "campos" normales de la definicion de tipo) y responde que
ese fieldId (null) es de solo lectura. Se eliminaron esas entradas de
build_vulnerability_payloads()/build_asset_payloads(); FIELD_MAP_* las deja
solo como referencia documentada, ya no se usan para construir field
entries.

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

CORREGIDO EN ESTA SESION (3) — con los 2 Assets ya creandose de verdad
(confirmado con una carga real), la Vulnerability fallo especificamente en
el campo MULTI_VALUE_ENUM (External System...:Severity) con un error 400
MUY explicito del backend:
    "Unrecognized field \"value\" (class
    com.ibm.openpages.api.grc.rest.model.v2.MultiEnumFieldType), not
    marked as ignorable (3 known properties: \"values\", \"id\", \"name\")"
Es decir: para MULTI_VALUE_ENUM la clave real NO es "value" (que si es
correcta para ENUM_TYPE y el resto), sino "values" (plural). _field() ya
decide automaticamente la clave correcta segun si el campo esta en
_MULTI_ENUM_FIELDS.

Uso:
    from openpages_mapper import build_vulnerability_payloads, build_asset_payloads

    vuln_payloads = build_vulnerability_payloads(clean_df)
    asset_payloads = build_asset_payloads(clean_df)
"""
import json
import hashlib
import pandas as pd

# ---------------------------------------------------------------------------
# CONSTANTES EDITABLES
# ---------------------------------------------------------------------------

TYPE_NAME_VULNERABILITY = "Vulnerability"
TYPE_NAME_ASSET = "Asset"  # name tecnico real; label en la UI es "Asset2"

# Campo -> nombre de campo real en OpenPages (Vulnerability)
# NOTA: "name" y "description" se dejan aqui solo como referencia/documentacion
# -- YA NO se usan para construir entradas dentro de "fields". Son atributos
# de sistema que la API v2 espera exclusivamente en el nivel superior del
# payload ("name"/"description"), NUNCA como field. Incluirlos tambien como
# field (como se hacia antes) hacia que la API no pudiera resolverles un
# fieldId real y respondiera "fieldId : null is read only and cannot be
# changed." -- esa fue la causa raiz real del error 400 que persistio a
# traves de varios intentos de arreglo de formato.
FIELD_MAP_VULNERABILITY = {
    # Base -- NO enviar como field, ver nota arriba
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
    # Confirmado via GET /v2/types/127 (inspect_type_fields.py): campo real
    # FLOAT_TYPE, encaja directo con definition.cvss3.base_score de Tenable
    # (0-10, sin perdida de precision vs. derivar desde el bucket categorico).
    "cvss_decimal": "External System - Application Vulnerability:CVSS_decimal",
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
# NOTA: "host_name" (-> "Name") se deja aqui solo como referencia -- YA NO se
# usa para construir una entrada dentro de "fields". Ver nota equivalente en
# FIELD_MAP_VULNERABILITY sobre por que "Name" nunca debe ir como field.
FIELD_MAP_ASSET = {
    "host_name": "Name",  # NO enviar como field, ver nota arriba
    "ipv4": "Demo-Asset:IP Address",
    "operating_system": "Demo-Asset:Operating System",
    "tags": "Demo-Asset:Tags",
    "asset_type": "Demo-Asset:Asset Type",           # ENUM: Desktops, Servers, Networks
    "confidentiality": "Demo-Asset:Confidentiality", # ENUM: High, Medium, Low
    "managed_state": "Demo-Asset:Managed State",     # ENUM: Managed, Unmanaged
    # Confirmados via GET /v2/types/136 (inspect_type_fields.py). Se usan
    # para reflejar la clasificacion "Joya de la Corona" (clean_engine.py,
    # es_joya_corona/clasificacion_joyas) en campos reales de OpenPages,
    # en vez de que esa clasificacion se quede solo en el Excel de salida.
    "data_classification_level": "Demo-Asset:Data Classification Level",  # ENUM: Public, Internal, Confidential
    "risk_score": "Demo-Asset:RiskScore",                                  # ENUM: High, Medium, Low
}

ASSET_ENUM_VALUES = {
    "Demo-Asset:Asset Type": ["Desktops", "Servers", "Networks"],
    "Demo-Asset:Confidentiality": ["High", "Medium", "Low"],
    "Demo-Asset:Managed State": ["Managed", "Unmanaged"],
    "Demo-Asset:Data Classification Level": ["Public", "Internal", "Confidential"],
    "Demo-Asset:RiskScore": ["High", "Medium", "Low"],
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
    "Demo-Asset:Data Classification Level",
    "Demo-Asset:RiskScore",
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
    """Construye un elemento de campo en el formato REAL de la API v2.

    Confirmado con una carga real: para la mayoria de los campos es
    simplemente {"name": ..., "value": ...}. PERO para campos
    MULTI_VALUE_ENUM (ver _MULTI_ENUM_FIELDS) la clase Java del backend
    (com.ibm.openpages.api.grc.rest.model.v2.MultiEnumFieldType) NO
    reconoce "value" -- espera la clave "values" (plural). El error real
    devuelto por la API fue:
        "Unrecognized field \"value\" (class ...MultiEnumFieldType), not
        marked as ignorable (3 known properties: \"values\", \"id\", \"name\")"
    Por eso este helper decide la clave segun si el nombre de campo esta
    en _MULTI_ENUM_FIELDS, en vez de usar siempre "value"."""
    key = "values" if name in _MULTI_ENUM_FIELDS else "value"
    return {"name": name, key: value}


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
        # BUGFIX: antes el name era solo VUL_{asset}_{port}. Un mismo activo
        # puede tener MAS de una vulnerabilidad distinta en el mismo puerto
        # (ej. dos hallazgos separados de Tenable sobre el 445/SMB) -- en
        # ese caso colisionaban en el mismo name, y como
        # load_to_openpages.py usa "name" como clave de deduplicacion
        # (vuln_id_mapping.json), la segunda vulnerabilidad se omitia
        # silenciosamente por "ya existe" sin cargarse nunca. Se agrega un
        # hash corto y deterministico de definition.name a la clave para
        # que cada hallazgo distinto tenga un name unico, incluso
        # compartiendo activo+puerto.
        def_name = str(row.get("definition.name", ""))
        def_hash = hashlib.sha256(def_name.encode("utf-8")).hexdigest()[:8]
        vuln_name = f"VUL_{row['asset_id_canonical']}_{row['port']}_{def_hash}"
        severity_op = _severity_openpages(row["severity"])
        field_list = [
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

        # CVE ID (STRING_TYPE): Tenable trae 0..N CVEs separados por coma en
        # definition.cve; se manda tal cual como texto (el campo real no es
        # una lista estructurada, es un STRING_TYPE simple). Se omite el
        # campo por completo si no hay CVE (evita mandar "nan"/vacio).
        cve_raw = row.get("definition.cve")
        if pd.notna(cve_raw) and str(cve_raw).strip():
            field_list.append(_field(fm["cve"], str(cve_raw).strip()))

        # CVSS score (FLOAT_TYPE real, confirmado via inspect_type_fields.py):
        # se manda el valor numerico de Tenable tal cual, sin pasar por el
        # bucket categorico de 5 niveles -- mayor precision para GRC.
        cvss_raw = row.get("definition.cvss3.base_score")
        if pd.notna(cvss_raw):
            field_list.append(_field(fm["cvss_decimal"], float(cvss_raw)))
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
            _field(fm["ipv4"], str(row["asset.ipv4_addresses"])),
            _field(fm["operating_system"], str(row["asset.operating_system"])),
            _field(fm["tags"], str(row.get("asset.tags", ""))),
        ]

        # Clasificacion "Joya de la Corona" (clean_engine.py: es_joya_corona /
        # clasificacion_joyas), mapeada a campos reales confirmados de
        # OpenPages en vez de quedarse solo en el Excel de salida. Solo se
        # manda si el pipeline corrio con el listado de joyas (columna
        # presente); si no, se omite el field por completo (no se asume
        # "no es joya" cuando en realidad no se evaluo).
        if "es_joya_corona" in row.index and bool(row.get("es_joya_corona")):
            field_list.append(
                _field(
                    fm["data_classification_level"],
                    _plain_or_enum_value(fm["data_classification_level"], "Confidential"),
                )
            )
            field_list.append(
                _field(fm["risk_score"], _plain_or_enum_value(fm["risk_score"], "High"))
            )
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
