# Limpieza de Vulnerabilidades — Tenable (Actinver)

Aplicación web que limpia exports de Tenable en los que un mismo activo (servidor,
equipo de red, etc.) aparece duplicado por inconsistencias en el campo
`asset.operating_system` — típicamente porque distintas corridas de escaneo
resuelven el sistema operativo con distinto nivel de detalle o confianza,
partiendo el mismo activo físico en dos o más registros.

**App en producción:** desplegada en IBM Cloud Code Engine, build automático
desde este repositorio (rama `main`, `Dockerfile` en la raíz).

## Qué resuelve

Un export de Tenable puede traer el mismo host repetido con distinto
`operating_system` (ej. "Windows Server 2012" vs "Windows Server 2012 R2
Standard Build 9600"), lo que genera:
- Vulnerabilidades duplicadas (misma vuln, mismo puerto, contada dos veces)
- Conteos de activos inflados
- Datos poco confiables para procesos posteriores (ej. ingesta a un GRC como
  IBM OpenPages)

## Cómo lo resuelve

`clean_engine.py` contiene la lógica pura (sin UI, testeable por separado):

1. **Identidad del activo**: agrupa filas por `asset.host_name` normalizado;
   si no hay hostname, usa `asset.ipv4_addresses` como respaldo. Genera un
   `asset_id_canonical` (hash SHA-256 corto) estable entre corridas.
2. **Sistema operativo canónico**: cuando un mismo activo tiene más de un
   valor de SO registrado, conserva el más específico (heurística por
   longitud + presencia de build numbers). Todas las variantes vistas quedan
   registradas en `os_variants_seen`, no se descarta información.
3. **Deduplicación de vulnerabilidades**: una vulnerabilidad se considera
   la misma cuando coincide activo + `definition.name` + `port`. Si se repite,
   se conserva una sola fila, priorizando mayor severidad y fecha más reciente.
4. **Auditoría**: cada fusión queda registrada (qué filas originales se
   colapsaron, cuál se conservó y por qué) — nada se descarta en silencio.
5. **Clasificación "Joya de la Corona" (opcional)**: si se carga un archivo
   `listado_joyas.xlsx` (columna `Joyas` con IPs), el motor compara cada
   `asset.ipv4_addresses` contra ese listado (soporta múltiples IPs por
   celda, separadas por coma/`;`/espacio). Si hace match:
   - Se marca `es_joya_corona = True`.
   - Se valida además que `asset.tags` contenga la etiqueta
     `01.ACT.JOYAS` (campo `tiene_tag_joyas`).
   - `clasificacion_joyas` resume el resultado cruzado:
     - `"Joya de la Corona (validada por tag)"` — IP en listado y tag presente.
     - `"Joya de la Corona (IP en listado, SIN tag 01.ACT.JOYAS)"` —
       inconsistencia: la IP es crítica según el listado pero el activo no
       trae la clasificación formal esperada en OpenPages/Tenable.
   - Si no se carga el listado de joyas, estos campos quedan vacíos/`False`
     y el resto del pipeline funciona igual que antes (retrocompatible).

## Estructura del repo

```
├── app.py                    # Interfaz Streamlit (carga, insights, descarga)
├── clean_engine.py            # Lógica de limpieza, sin dependencias de UI
├── openpages_mapper.py         # Mapeo del Excel limpio a payloads JSON de OpenPages
├── load_to_openpages.py         # Script de carga real (POST) contra la API v2 de OpenPages,
│                                  con deduplicación de Assets y Vulnerabilities entre corridas
├── inspect_type_fields.py       # Utilidad de solo lectura: lista los campos reales de un tipo
│                                  (Vulnerability/Asset) via GET /v2/types/{id}
├── cleanup_test_vulnerabilities.py  # Utilidad de una sola vez: borra objetos de prueba y limpia
│                                      vuln_id_mapping.json (dry-run por default, --confirm para borrar)
├── requirements.txt
├── Dockerfile                   # Build para Code Engine (puerto 8080 vía $PORT)
├── .streamlit/config.toml       # Tema claro forzado (paleta IBM Carbon)
└── DEPLOY.md                     # Guía paso a paso de despliegue en Code Engine
```

> **Nota:** `load_to_openpages.py`, `inspect_type_fields.py` y
> `cleanup_test_vulnerabilities.py` no forman parte del build de Code Engine
> (no están en el `Dockerfile`, que solo empaqueta la app Streamlit). Son
> scripts que se corren localmente/manualmente contra la instancia real de
> OpenPages, típicamente vía `--dry-run` primero y luego la acción real.

## Exportación a OpenPages (`openpages_mapper.py`)

Genera, a partir del Excel limpio, dos conjuntos de payloads JSON listos para
`POST /openpages/api/v2/contents` (mismo patrón usado en `ejemplo_carga.py`):

- **`assets`**: un payload por activo único (`asset_id_canonical`) para el
  objeto **Asset/System** (host, IP, SO, tags).
- **`vulnerabilities`**: un payload por fila del Excel limpio para el objeto
  **Vulnerability**.

Puntos importantes a tener en cuenta antes de usar esto contra producción:

- **Vulnerability y Asset/System son objetos distintos.** `host_name`,
  `ipv4` y `operating_system` no son campos de Vulnerability — viven en
  Asset/System (name técnico real `Asset`, label en UI `Asset2`), y se
  relacionan vía `primary_parent_id`. Cada payload de Vulnerability trae
  `primary_parent_id: null` y un campo auxiliar `_pending_asset_lookup`
  con la clave `asset_id_canonical`; `load_to_openpages.py` resuelve ese
  lookup en tiempo de carga contra `asset_id_mapping.json`.
- **`type_definition_id` también viene en `null`**: se resuelve en tiempo
  de ejecución llamando a `get_all_types(...)`, no se hardcodea porque
  cambia por instancia/ambiente. Confirmado contra la instancia de prueba
  (TechZone, OpenPages 9.2): `Vulnerability` id=127, `Asset` (Asset2) id=136.
- **Esquema de payload validado contra la API v2 real** (no v1): claves raíz
  en snake_case (`type_definition_id`, `primary_parent_id`), `fields` como
  array plano de `{"name":..., "value":...}` (o `{"name":..., "values":[...]}`
  para campos `MULTI_VALUE_ENUM`) — ver detalle y ejemplos en el encabezado
  de `openpages_mapper.py`.
- **Nombres de campo son constantes editables**, no hardcodeados dentro de
  la lógica: `FIELD_MAP_VULNERABILITY` y `FIELD_MAP_ASSET` en
  `openpages_mapper.py`. Los nombres usados hoy (`Demo-Vulner:*`,
  `External System - Application Vulnerability:*`, `Demo-Asset:*`) vienen
  de la instancia de prueba TechZone y ya están **confirmados como
  poblados con datos reales** en ese ambiente — pero siguen siendo la
  categoría de **demo**, no la categoría personalizada de producción de
  Actinver. Antes de apuntar el loader contra el ambiente productivo de
  Actinver hay que confirmar los nombres reales de esa instancia (vía
  plantilla FastMap o `GET /v2/types`) y actualizar esas dos constantes.
- **Mapeo de severidad**: Tenable trae 5 niveles (Critical/High/Medium/
  Low/Info); el campo `External System - Application Vulnerability:Severity`
  en la instancia de prueba solo acepta 3 (High/Medium/Low, confirmado por
  API). El mapeo usado (`SEVERITY_MAP` en `openpages_mapper.py`) colapsa
  Critical→High e Info→Low — a validar con el equipo de GRC si esa es la
  equivalencia correcta para producción.

Desde la app, el botón "Descargar payloads OpenPages (.json)" en el Paso 5
genera este archivo listo para usar como insumo de `load_to_openpages.py`.

### Campos adicionales confirmados y mapeados (CVE, CVSS, Joya de la Corona)

Además del mapeo base, se confirmaron contra el esquema real de la instancia
(vía `inspect_type_fields.py`, que lista todos los `field_definitions` de un
tipo con `GET /v2/types/{id}`) y ya están implementados en
`openpages_mapper.py`:

- **CVE**: `definition.cve` de Tenable → `Demo-Vulner:CVE ID` (STRING_TYPE).
  Se manda tal cual (puede traer varios CVEs separados por coma); se omite
  el campo si la vulnerabilidad no tiene CVE asociado.
- **CVSS**: `definition.cvss3.base_score` de Tenable → `External System -
  Application Vulnerability:CVSS_decimal` (FLOAT_TYPE real, confirmado por
  API) — más preciso que derivar la severidad desde el bucket categórico de
  5 niveles de Tenable.
- **Joya de la Corona**: cuando `clean_engine.py` marca `es_joya_corona =
  True`, el Asset correspondiente se manda con `Demo-Asset:Data
  Classification Level = Confidential` y `Demo-Asset:RiskScore = High`
  (ambos ENUM_TYPE reales, confirmados por API). Los assets que no son
  Joya de la Corona no llevan estos dos campos en absoluto.

Campos evaluados pero **descartados** por no tener match real en el esquema
de la instancia de prueba: `exploited_by_malware` de Tenable no tiene
equivalente (los candidatos más cercanos, `Ease of Exploitation`/
`CVSS_Exploitability`, miden facilidad teórica de explotación, no
explotación real confirmada — mapearlos sería engañoso). `state` de Tenable
(`ACTIVE`/`RESURFACED`/`NEW`) tiene un match parcial en `OPSS-Vuln:Assessment
Status` (`Re-Opened` ≈ `RESURFACED`), pero esa categoría `OPSS-Vuln:*` nunca
se ha visto poblada con datos reales en esta instancia — pendiente de
confirmar con el equipo de GRC antes de activarla.

### Bugfix: colisión de nombres cuando un activo tiene 2+ vulnerabilidades en el mismo puerto

El `name` de cada Vulnerability se construía como
`VUL_{asset_id_canonical}_{port}` (solo activo + puerto). Con datos reales
apareció el caso de un mismo activo con **dos vulnerabilidades distintas en
el mismo puerto** (ej. dos hallazgos de Tenable sobre el 445/SMB), lo cual
generaba el mismo `name` para ambas. Como `load_to_openpages.py` usa ese
`name` como clave de deduplicación (`vuln_id_mapping.json`), la segunda
vulnerabilidad se omitía silenciosamente por "ya existe" — se perdía sin
ningún error visible.

**Fix**: el `name` ahora incluye un hash corto y determinístico de
`definition.name`: `VUL_{asset_id}_{port}_{hash8}`. Esto es un cambio de
esquema — cualquier `vuln_id_mapping.json` generado antes de este fix queda
con claves obsoletas (sin hash) que no van a matchear contra los nombres
nuevos. Se usó `cleanup_test_vulnerabilities.py` para borrar los 2
objetos de prueba creados con el esquema viejo y limpiar sus entradas del
mapping, permitiendo que se recrearan limpios con el esquema nuevo — ya
validado end-to-end (API + UI) contra la instancia real.

**De dónde sale cada pieza del `name`** (ej.
`VUL_AST-4af90e10eaca_3389_bb4caef8`, tal como se ve en la UI de OpenPages)
— ninguna de estas piezas existe como texto literal en el Excel limpio, se
arman en tiempo de ejecución dentro de `build_vulnerability_payloads`:

| Pieza | De dónde sale |
|---|---|
| `VUL_` | Prefijo literal fijo en el código (de "**VUL**nerability"), solo para que el nombre se distinga a simple vista de un Asset (que usa el prefijo `AST-`) al verlo en el grid de OpenPages. |
| `AST-4af90e10eaca` | Columna `asset_id_canonical` del Excel limpio (generada por `clean_engine.py`: hash SHA-256 corto del hostname/IP del activo). |
| `3389` | Columna `port` del Excel limpio, tal cual. |
| `bb4caef8` | `hashlib.sha256(definition.name).hexdigest()[:8]` — hash de 8 caracteres sobre la columna `definition.name` (ej. `"SSL Certificate Cannot Be Trusted"`). Es lo que agregó el fix de esta sección; antes el `name` no incluía este hash y por eso colisionaba. |

Es decir: activo + puerto + huella digital de a qué vulnerabilidad
específica corresponde, para poder leer el nombre en el grid sin tener que
abrir el registro.

### Bugfix: error 500 `OP-03381` por campo `output` demasiado largo (>4000 bytes)

En la carga real del lote completo (43 Assets + 50 Vulnerabilities), una
vulnerabilidad falló con:

```
OP-03381: The specified value for "3796" is too long. The 4011 characters
entered (4011 bytes) exceeds the maximum size of 4000 bytes.
```

El atributo `3796` es `External System - Application Vulnerability:Issue
Type`, mapeado desde la columna `output` del Excel limpio (`fm["scan_output"]`
en `build_vulnerability_payloads`). Tenable puede generar `output` muy largo
en hallazgos con múltiples combinaciones reportadas (ej. Logjam, listando
varias combinaciones SSL/TLS/Diffie-Hellman), y OpenPages rechaza cualquier
STRING_TYPE que exceda 4000 bytes UTF-8.

**Fix**: se agregó `_truncate_to_byte_limit()` en `openpages_mapper.py`, que
trunca el valor de `output` a `MAX_SCAN_OUTPUT_BYTES = 3990` bytes (10 bytes
de margen bajo el límite real), agregando el sufijo `[...truncado...]` cuando
aplica. Se aplica automáticamente en `build_vulnerability_payloads` antes de
armar el `field` de `scan_output`. Validado contra el registro real que
había fallado (`AST-db41b2c9198c`, Logjam): el `output` de 4011 bytes originales
queda en exactamente 3990 bytes en el payload, y en la re-carga con este fix
la vulnerability se creó sin error.

### Incidente de deploy: `Segmentation fault` en Code Engine por versiones no fijadas de `numpy`/`pyarrow`

Después de actualizar `openpages_mapper.py` (fix anterior) y redesplegar, la
app dejó de mostrar resultados: la limpieza corría bien (los insights de
"Paso 2" se calculaban correctamente), pero la app moría silenciosamente en
"Paso 3"/"Paso 4" (tablas con `st.dataframe`, generación del Excel o
Altair), sin traceback — solo `Segmentation fault` en los logs de Code
Engine (`ibmcloud ce application logs --name app-actinver`).

**Causa**: `requirements.txt` fijaba `pandas==2.2.2` pero no fijaba
`numpy` ni `pyarrow` (dependencias transitivas usadas por `pandas` y por
`st.dataframe` internamente para convertir a Arrow). En un rebuild nuevo de
la imagen, `pip install` jaló las últimas versiones disponibles de esas dos
librerías al momento del build, con una combinación binaria incompatible con
`pandas==2.2.2` en la imagen `python:3.11-slim` — un error a nivel de
extensión C que no genera excepción de Python, solo tumba el proceso.

**Fix**: fijar explícitamente `numpy` y `pyarrow` en `requirements.txt`:

```
streamlit==1.38.0
pandas==2.2.2
numpy==1.26.4
pyarrow==16.1.0
openpyxl==3.1.5
altair==5.3.0
```

También se agregó `faulthandler.enable()` al inicio de `app.py` (antes de
cualquier otro import), para que un futuro segfault deje un traceback de
bajo nivel en los logs en vez de morir en silencio.

**Lección para futuros cambios de dependencias**: cualquier librería que se
agregue o actualice en `requirements.txt` debe fijar también sus
dependencias transitivas relevantes (`numpy`, `pyarrow`), no solo el
paquete de primer nivel — de lo contrario cada rebuild de la imagen puede
jalar versiones distintas sin que el código haya cambiado.

### Carga real a OpenPages (`load_to_openpages.py`)

Script separado (no forma parte de la app Streamlit ni de su Dockerfile)
que toma `openpages_payloads.json` y hace el `POST` real (o simulado, con
`--dry-run`) contra `/openpages/api/v2/contents` de la instancia configurada.

- **Deduplicación entre corridas**: mantiene `asset_id_mapping.json`
  (`asset_id_canonical` → ID real de OpenPages) y `vuln_id_mapping.json`
  (`name` de la Vulnerability → ID real de OpenPages). Si una clave ya
  existe en el mapping correspondiente, se omite el POST — así una
  re-ingesta del mismo archivo (o de un archivo con overlap) no duplica
  Assets ni Vulnerabilities ya cargados.
- **`--dry-run`**: simula la carga (IDs `DRYRUN-*`) sin llamar a la API ni
  persistir los mappings, para revisar antes de enviar de verdad —
  incluye avisos de valores de campo tipo ENUM que no coincidan con lo
  esperado (`AVISO enum: ...`), que no bloquean el envío pero conviene
  revisar antes de la carga real.
- **Estado actual**: pipeline completo (clean_engine → mapper → loader →
  OpenPages → UI) validado end-to-end contra la instancia real, incluyendo
  los campos nuevos (CVE, CVSS, Joya de la Corona) y el fix de colisión de
  nombres — confirmado tanto por API (`carga_reporte.json`, incluyendo
  `primary_parent_id` correcto incluso para un Asset creado en la misma
  corrida) como visualmente en la UI. El lote completo (43 Assets + 50
  Vulnerabilities) está consolidado en `openpages_payloads_full.json.bak`,
  pendiente de renombrar a `openpages_payloads.json`, correr `--dry-run` y,
  si se ve limpio, la carga real.

### Configuración de la instancia OpenPages (fuera del código)

En la instancia de prueba (TechZone, OpenPages 9.2) el tipo `Asset`
(label `Asset2`) no tenía ninguna **View** configurada, lo cual impedía
verlo en la interfaz web aunque los datos ya estuvieran cargados
correctamente vía API (`"No view was found for Asset2"`). Se crearon y
publicaron dos Views nuevas — `Demo-Task-Asset-ITG` (detalle) y
`Demo-Grid-Asset-ITG` (listado), ambas Enabled/Published/Default = Yes —
replicando el patrón ya existente para `Vulnerability`. Esto es un cambio
de configuración de la instancia, no de los scripts: si se apunta el
loader a una instancia nueva (ej. producción de Actinver), hay que
verificar que el tipo `Asset` tenga Views equivalentes ahí también.

### Acceso directo a la UI de OpenPages (grids de Asset2 y Vulnerability)

Los tipos `Asset` (label `Asset2`) y `Vulnerability` **no están enlazados
a ninguna entrada del menú de navegación estándar** ("IT Governance" en el
menú solo tiene entradas para otros tipos — "Assets" ahí navega al tipo
genérico `Resource`, que trae ~345 registros de demo sin relación con este
proyecto, y "IT Systems" navega al tipo `RiskEntity`, tampoco relacionado).
Para ver los datos reales cargados por este pipeline hay que usar las URLs
directas al grid, construidas con el `Name` técnico real del tipo (no el
label que se ve en pantalla):

- **Assets2**: `http://na4.services.cloud.techzone.ibm.com:47373/openpages/app/jspview/react/grc/grid/Asset?objectTypeName=Asset`
- **Vulnerabilities**: `http://na4.services.cloud.techzone.ibm.com:47373/openpages/app/jspview/react/grc/grid/Vulnerability?objectTypeName=Vulnerability`

Ambas confirmadas funcionando (muestran los registros reales cargados por
`load_to_openpages.py`, incluyendo campos de CVE/CVSS/Joya de la Corona y
la relación `primary_parent_id` correcta). Recomendable guardarlas como
favoritos del navegador mientras no se resuelva el pendiente de abajo.

Pendiente de configuración (no bloquea la carga, pero conviene resolverlo
para que el equipo de GRC no tenga que usar URLs directas): enlazar el tipo
`Asset`/Asset2 y `Vulnerability` a una entrada visible del menú de
navegación "IT Governance", igual que ya lo están otros tipos.

## Archivo de entrada opcional: listado de Joyas de la Corona

Además del export de Tenable, la app acepta opcionalmente un segundo
archivo `.xlsx` con una sola columna llamada `Joyas`, donde cada fila es
una IP considerada crítica para el negocio ("Joya de la Corona"). Ejemplo:

| Joyas          |
|----------------|
| 192.168.223.18 |
| 10.10.110.88   |

Si se carga, el archivo limpio final incluye las columnas `asset.tags`,
`es_joya_corona`, `tiene_tag_joyas` y `clasificacion_joyas` (ver detalle en
la sección "Qué resuelve" más arriba). Si no se carga, la app funciona
exactamente igual que antes de esta funcionalidad.

## Uso local

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Uso programático del motor (sin UI)

```python
from clean_engine import clean_tenable_export

result = clean_tenable_export("Vul_IBM.xlsx")
result.clean_df     # DataFrame limpio
result.audit_df      # Detalle de fusiones
result.insights       # Métricas resumen (dict)
```

## Despliegue

Ver `DEPLOY.md`. Resumen: Code Engine construye la imagen directamente desde
este repo con el `Dockerfile` de la raíz (`Strategy: Dockerfile`), la sube al
namespace de IBM Container Registry configurado, y despliega. Cada cambio en
`main` requiere disparar manualmente **Rerun build** (o **Run build and
deploy** al editar la configuración) — no hay redeploy automático por push
configurado todavía.

---

## Mejoras y pendientes a revisar

Este es un **piloto**. Antes de que la persona final dependa de esto para
alimentar procesos formales (como OpenPages), vale la pena revisar:

### Reglas de negocio
- [ ] **Validar la regla "más específico gana"** para resolver el SO con más
  volumen de datos real — con 59 filas no hubo ningún caso ambiguo, pero con
  miles de filas podrían aparecer empates o casos donde "más específico" no
  sea "más correcto" (ej. un escaneo viejo con detalle vs uno reciente
  genérico pero más confiable).
- [ ] **Definir qué pasa si dos vulnerabilidades "duplicadas" tienen
  severidad distinta** de forma legítima (no por error de SO, sino porque de
  verdad cambió entre escaneos) — hoy el motor se queda con la más alta, sin
  distinguir el motivo.
- [ ] Revisar si conviene deduplicar también por `definition.cve` además de
  `definition.name`, para los casos donde el nombre de la definición cambia
  de fraseo entre versiones del plugin de Tenable pero el CVE es el mismo.
- [ ] **Matching de "Joya de la Corona" por IP exacta**: hoy la comparación
  contra `listado_joyas.xlsx` es string-a-string. Si el listado llegara a
  incluir rangos o notación CIDR en vez de IPs individuales, habría que
  extender `load_joyas_ip_set`/`extract_ips` en `clean_engine.py` para
  resolver membresía de rango en vez de igualdad exacta.

### Integración con OpenPages

OpenPages ITG (IT Governance) tiene un objeto nativo **Vulnerability**,
pensado justo para este tipo de dato (escaneos automatizados de
vulnerabilidades de activos), relacionado con objetos **Asset/System**.
ORM (Operational Risk Management) no captura vulnerabilidades directamente
— ahí entraría solo si una vulnerabilidad crítica se decide escalar como
Riesgo operacional, vía un link entre el objeto Vulnerability/Asset y un
objeto Risk. Esa relación ITG↔ORM es una decisión de gobierno que Actinver
tiene que definir, no algo que se resuelva a nivel de este pipeline.

Pendientes concretos antes de automatizar la entrega a OpenPages:

- [x] Generar los payloads JSON con la forma que espera la API v2 —
  resuelto en `openpages_mapper.py` (`build_openpages_export`), con
  nombres de campo dejados como constantes editables. Esquema validado
  contra la API v2 real (snake_case, `fields` como array plano).
- [x] Tabla de correspondencia `asset_id_canonical` ↔ ID real de OpenPages
  — resuelta en `load_to_openpages.py` vía `asset_id_mapping.json` (y, para
  Vulnerabilities, `vuln_id_mapping.json`), con deduplicación automática
  entre corridas para no duplicar Assets ni Vulnerabilities en re-ingestas.
- [x] Confirmar el mecanismo de carga: se optó por REST API directa
  (`load_to_openpages.py`, con soporte `--dry-run`) en vez de plantilla
  FastMap, para poder automatizar el envío desde el pipeline.
- [x] Views de la instancia para el objeto `Asset`/`Asset2` — creadas y
  publicadas (`Demo-Task-Asset-ITG`, `Demo-Grid-Asset-ITG`); antes de esto
  los Assets se cargaban bien vía API pero no se podían ver en la UI.
- [x] Agregar `definition.cve` y `definition.cvss3.base_score` a la salida
  — confirmados contra el esquema real (`inspect_type_fields.py`) y
  mapeados a `Demo-Vulner:CVE ID` y `External System - Application
  Vulnerability:CVSS_decimal` respectivamente. Validado end-to-end.
- [x] Clasificación "Joya de la Corona" mapeada a campos reales de
  OpenPages (`Demo-Asset:Data Classification Level` = Confidential,
  `Demo-Asset:RiskScore` = High) en vez de quedarse solo en el Excel de
  salida. Validado end-to-end (API + UI).
- [x] Bugfix: colisión de `name` de Vulnerability cuando un activo tiene
  2+ vulnerabilidades distintas en el mismo puerto — el `name` ahora
  incluye un hash de `definition.name`. Ver sección de bugfix más arriba.
- [ ] **Confirmar si `Demo-Vulner:`/`Demo-Asset:` es la categoría real de
  producción de Actinver o solo la de la instancia de prueba (TechZone).**
  Ya está confirmado que en la instancia de prueba estos campos están
  poblados con datos reales y funcionan end-to-end (API + UI), pero sigue
  siendo la categoría de **demo** de esa instancia. Antes de apuntar el
  loader al ambiente productivo real de Actinver, pedir el query/plantilla
  equivalente contra ese ambiente y actualizar `FIELD_MAP_VULNERABILITY` y
  `FIELD_MAP_ASSET` en `openpages_mapper.py` si los nombres difieren.
- [ ] Confirmar si el objeto Vulnerability de ITG ya está habilitado en la
  instancia **productiva** de Actinver (depende del licenciamiento/
  configuración activa) — la instancia de prueba TechZone ya lo tiene.
- [ ] Enlazar los tipos `Asset`/Asset2 y `Vulnerability` a una entrada
  visible del menú de navegación "IT Governance" — hoy solo son accesibles
  vía URL directa (ver sección "Acceso directo a la UI de OpenPages" más
  arriba). No bloquea la carga, pero el equipo de GRC no debería depender
  de URLs manuales para uso diario.
- [ ] Validar el mapeo de severidad Tenable (5 niveles) → OpenPages (3
  niveles, confirmado por API en la instancia de prueba) con el equipo de
  GRC — ver `SEVERITY_MAP` en `openpages_mapper.py`.
- [x] Correr `load_to_openpages.py --dry-run` con el lote completo (43
  Assets + 50 Vulnerabilities) y luego la carga real — completado: 43/43
  Assets y 49/50 Vulnerabilities en el primer intento. La vulnerability
  restante falló por `OP-03381` (campo `output` > 4000 bytes); ver bugfix
  del truncado más arriba. Con el fix aplicado, el reintento del registro
  faltante quedó pendiente de confirmar en la próxima carga real.
- [ ] **`state`/`exploited_by_malware` de Tenable**: evaluados contra el
  esquema real, sin match limpio (ver sección de campos adicionales más
  arriba). Pendiente de decisión con el equipo de GRC antes de mapear
  `state` a `OPSS-Vuln:Assessment Status` (categoría no usada aún en esta
  instancia) o de agregar un campo nuevo para `exploited_by_malware`.
- [ ] Agregar un `external_id`/`source_system_id` estable de Tenable (si
  existe) para que reimportaciones actualicen el mismo registro en vez
  de crear uno nuevo.
- [ ] `merged_duplicate_count` y `os_variants_seen` probablemente vayan a un
  campo de notas/texto libre en OpenPages, no a un campo estructurado —
  confirmar contra la plantilla real de producción.

### Escala y rendimiento
- [ ] Este piloto se probó con 59 filas. **No se ha probado con el volumen
  real de producción.** Si el archivo real es de miles/decenas de miles de
  filas, conviene correr una prueba de carga antes de considerarlo listo
  (tanto para tiempo de procesamiento de pandas como para el límite de
  200MB por archivo configurado en Streamlit).
- [ ] Si el volumen resulta muy grande, revisar memoria asignada en Code
  Engine (`Resources & scaling`) — hoy está en el default del piloto.

### Seguridad y operación
- [ ] El API key usado para el `registry secret` de Code Engine se generó
  para el piloto — revisar que tenga el rol mínimo necesario (`Writer` sobre
  Container Registry) en vez de permisos amplios de cuenta.
- [ ] La app no persiste ningún dato entre sesiones (cada carga es
  independiente, nada se guarda en el servidor). Confirmar que esto es
  aceptable o si se requiere historial/trazabilidad de corridas — de ser así,
  se necesitaría IBM Cloud Object Storage o similar.
- [ ] No hay control de acceso en la URL pública de la app — cualquiera con
  el link puede usarla. Evaluar si se necesita autenticación (ej. IBM App ID)
  antes de compartirla más ampliamente, dado que procesa datos de
  vulnerabilidades internas.
- [ ] Configurar redeploy automático (webhook de GitHub → Code Engine) si el
  ciclo de "empujar cambio → disparar build manual" se vuelve tedioso.
- [x] Fijar `numpy`/`pyarrow` en `requirements.txt` — un rebuild sin estas
  versiones fijas causó un `Segmentation fault` en producción (ver
  incidente de deploy más arriba). Revisar esta misma precaución la
  próxima vez que se agregue o actualice cualquier dependencia con
  extensiones nativas en C (no solo el paquete de primer nivel).

### Experiencia de usuario
- [ ] Validar el flujo con la persona no técnica que lo va a usar en el día
  a día — el piloto se probó solo internamente.
- [ ] Considerar agregar validación de columnas al cargar el archivo (avisar
  claramente si falta alguna columna esperada, en vez de fallar con un error
  genérico de Python).
