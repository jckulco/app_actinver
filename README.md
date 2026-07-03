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

## Estructura del repo

```
├── app.py                 # Interfaz Streamlit (carga, insights, descarga)
├── clean_engine.py         # Lógica de limpieza, sin dependencias de UI
├── requirements.txt
├── Dockerfile               # Build para Code Engine (puerto 8080 vía $PORT)
├── .streamlit/config.toml   # Tema claro forzado (paleta IBM Carbon)
└── DEPLOY.md                 # Guía paso a paso de despliegue en Code Engine
```

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

### Integración con OpenPages
- [ ] `asset_id_canonical` es una clave **interna** de este pipeline, no un
  ID de negocio. Cuando OpenPages esté implementado, se necesita una tabla
  de correspondencia (`asset_id_canonical` ↔ ID de activo en OpenPages) para
  no duplicar activos en cada re-ingesta.
- [ ] Confirmar con el equipo de OpenPages el formato de importación esperado
  (columnas, tipos de dato, si acepta `.xlsx` o requiere CSV/API) antes de
  automatizar la entrega.

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
