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
├── app.py                 # Interfaz Streamlit (carga, insights, descarga)
├── clean_engine.py         # Lógica de limpieza, sin dependencias de UI
├── openpages_mapper.py      # Mapeo del Excel limpio a payloads JSON de OpenPages
├── requirements.txt
├── Dockerfile               # Build para Code Engine (puerto 8080 vía $PORT)
├── .streamlit/config.toml   # Tema claro forzado (paleta IBM Carbon)
└── DEPLOY.md                 # Guía paso a paso de despliegue en Code Engine
```

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
  Asset/System, y se relacionan vía `primary_parent_id`. Por eso cada
  payload de Vulnerability trae `primary_parent_id: null` y un campo
  auxiliar `_pending_asset_lookup` con la clave `asset_id_canonical` a
  resolver una vez que exista la tabla de correspondencia con el ID real
  del Asset/System en OpenPages (pendiente, ver sección de abajo).
- **`type_definition_id` también viene en `null`**: se resuelve en tiempo
  de ejecución llamando a `get_all_types(...)` (como en `ejemplo_carga.py`),
  no se hardcodea porque cambia por instancia/ambiente.
- **Nombres de campo son constantes editables**, no hardcodeados dentro de
  la lógica: `FIELD_MAP_VULNERABILITY` y `FIELD_MAP_ASSET` en
  `openpages_mapper.py`. Los nombres usados hoy vienen de un query de
  ejemplo (`objetos.json`) cuya categoría trae el prefijo `Demo-Vulner:` —
  es decir, probablemente la categoría de **demo** de OpenPages, no la
  categoría personalizada real de producción de Actinver. Antes de enviar
  contra producción, hay que confirmar los nombres reales (vía la
  plantilla FastMap pendiente) y actualizar esas dos constantes.
- **Mapeo de severidad**: Tenable trae 5 niveles (Critical/High/Medium/
  Low/Info); el esquema de ejemplo de OpenPages solo expone 3
  (High/Medium/Low). El mapeo usado (`SEVERITY_MAP` en
  `openpages_mapper.py`) colapsa Critical→High e Info→Low — a validar con
  el equipo de GRC si esa es la equivalencia correcta.

Desde la app, el botón "Descargar payloads OpenPages (.json)" en el Paso 5
genera este archivo listo para usar como insumo del script de carga real.

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
  nombres de campo dejados como constantes editables.
- [ ] **Confirmar si `Demo-Vulner:` es la categoría real de producción o
  la de demo.** Todo indica que es la de demo (nombre de la categoría lo
  delata). Hay que pedir el query/plantilla equivalente contra el
  ambiente productivo de Actinver y actualizar `FIELD_MAP_VULNERABILITY`
  y `FIELD_MAP_ASSET` en `openpages_mapper.py`.
- [ ] `asset_id_canonical` es una clave **interna** de este pipeline, no un
  ID de negocio. Se necesita una tabla de correspondencia
  (`asset_id_canonical` ↔ ID real del Asset/System en OpenPages) para no
  duplicar activos en cada re-ingesta — hoy los payloads de Vulnerability
  traen `primary_parent_id: null` y `_pending_asset_lookup` en su lugar.
- [ ] **Pedir al administrador de OpenPages el export de una plantilla
  FastMap vacía** de los objetos **Vulnerability** y **Asset/System**. Los
  nombres de campo son personalizables por cliente, así que no se puede
  asumir el esquema "de fábrica" — esa plantilla da los nombres reales para
  mapear cada columna de nuestro Excel limpio sin adivinar.
- [ ] Confirmar si el objeto Vulnerability de ITG ya está habilitado en la
  instancia de Actinver (depende del licenciamiento/configuración activa).
- [ ] Validar el mapeo de severidad Tenable (5 niveles) → OpenPages (3
  niveles observados) con el equipo de GRC — ver `SEVERITY_MAP` en
  `openpages_mapper.py`.
- [ ] Mapeo sugerido, a validar contra la plantilla real:
  - `asset.host_name`, `asset.ipv4_addresses`, `asset.operating_system` →
    atributos del objeto **Asset/System**
  - `definition.name`, `severity`, `port`, `output` → atributos del objeto
    **Vulnerability**
  - `severity` probablemente necesite mapearse a la escala de severidad
    que use OpenPages (puede no ser Critical/High/Medium/Low)
  - Agregar `definition.cve` a la salida si el objeto Vulnerability tiene
    campo para CVE — es una clave más confiable que `definition.name` para
    evitar duplicados entre escaneos
  - Agregar un `external_id`/`source_system_id` estable de Tenable (si
    existe) para que reimportaciones actualicen el mismo registro en vez
    de crear uno nuevo
  - `merged_duplicate_count` y `os_variants_seen` probablemente vayan a un
    campo de notas/texto libre, no a un campo estructurado
- [ ] Confirmar el mecanismo de carga: plantilla FastMap (Excel/CSV) para
  cargas periódicas, o REST API para automatizar el envío directo desde
  esta app en vez de solo generar un archivo descargable.

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

### Experiencia de usuario
- [ ] Validar el flujo con la persona no técnica que lo va a usar en el día
  a día — el piloto se probó solo internamente.
- [ ] Considerar agregar validación de columnas al cargar el archivo (avisar
  claramente si falta alguna columna esperada, en vez de fallar con un error
  genérico de Python).
