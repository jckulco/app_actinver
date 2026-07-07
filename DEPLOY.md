# Despliegue en IBM Cloud Code Engine

## Requisitos previos
- IBM Cloud CLI instalado, con el plugin `code-engine`: `ibmcloud plugin install code-engine`
- Sesión iniciada: `ibmcloud login` (o `ibmcloud login --sso` si tu cuenta usa SSO)
- Un namespace en IBM Container Registry (icr.io)

## 1. Construir y subir la imagen a IBM Container Registry

```bash
ibmcloud cr login

# Ajusta <namespace> por el tuyo (ibmcloud cr namespace-list para verlo)
docker build -t icr.io/<namespace>/vuln-cleaner:v1 .
docker push icr.io/<namespace>/vuln-cleaner:v1
```

## 2. Crear (o seleccionar) el proyecto de Code Engine

```bash
ibmcloud ce project create --name vuln-cleaner-project
ibmcloud ce project select --name vuln-cleaner-project
```

## 3. Desplegar la aplicación

```bash
ibmcloud ce application create \
  --name vuln-cleaner \
  --image icr.io/<namespace>/vuln-cleaner:v1 \
  --registry-secret <tu-secreto-de-registro> \
  --port 8080 \
  --cpu 1 --memory 2G \
  --min-scale 0 --max-scale 3
```

- `--registry-secret`: si nunca has conectado Code Engine a tu Container Registry,
  créalo primero con `ibmcloud ce registry create --name my-icr --server icr.io --username iamapikey --password <tu-api-key>`
- `--min-scale 0` deja la app en cero instancias cuando nadie la usa (ahorra costo);
  la primera petición después de estar inactiva tarda unos segundos en "despertar" (cold start).
- `2G` de memoria es holgado para archivos de miles de filas; si el archivo real
  resulta ser mucho más grande, se puede subir sin cambiar el código.

## 4. Obtener la URL pública

```bash
ibmcloud ce application get --name vuln-cleaner --output url
```

Code Engine entrega HTTPS automáticamente, sin configuración adicional.

## 5. Actualizar la app después de un cambio de código

```bash
docker build -t icr.io/<namespace>/vuln-cleaner:v2 .
docker push icr.io/<namespace>/vuln-cleaner:v2
ibmcloud ce application update --name vuln-cleaner --image icr.io/<namespace>/vuln-cleaner:v2
```

## Notas
- La app no persiste nada entre sesiones: cada usuario carga su archivo, lo descarga
  limpio, y no queda ningún dato guardado en el servidor. Para el piloto esto es
  suficiente; si más adelante se necesita historial de corridas, se añadiría
  IBM Cloud Object Storage.
- Desde esta versión, la app acepta un segundo archivo `.xlsx` opcional (listado de
  IPs "Joya de la Corona", columna `Joyas`) para clasificar activos críticos. No
  requiere cambios de infraestructura ni de variables de entorno — no hay que
  actualizar nada en Code Engine por este cambio, solo redesplegar la imagen con el
  código nuevo (paso 5 de esta guía).
- Prueba local antes de desplegar: `docker build -t vuln-cleaner-local . && docker run -p 8080:8080 vuln-cleaner-local`
  y abre `http://localhost:8080`.
