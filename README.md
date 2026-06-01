[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/Chmod351/radar?color=green&label=version&sort=semver)](https://github.com/Chmod351/radar-service/releases)
![GitHub closed pull requests](https://img.shields.io/github/issues-pr-closed/Chmod351/radar-service?color=green) ![GitHub issues](https://img.shields.io/github/issues/Chmod351/radar-service?color=red) ![GitHub last commit (by committer)](https://img.shields.io/github/last-commit/Chmod351/radar-service) ![GitHub top language](https://img.shields.io/github/languages/top/Chmod351/radar-service?color=blue) ![](https://img.shields.io/github/license/Chmod351/radar-service.svg)

![Screenshot_from_2023-08-02_14-38-24-removebg-preview](https://github.com/user-attachments/assets/4cfed1a6-4c17-4e6f-afd9-55cb4c3efbb1)

#   RADAR: Reconnaissance & Advanced Data Analysis Runtime

Radar es una herramienta de interfaz de línea de comandos (CLI) de alta eficiencia desarrollada en TypeScript sobre el runtime Bun, diseñada para la automatización de reconocimiento (Recon) y la evaluación de la superficie de ataque externa de una organización.A diferencia de los scripts secuenciales tradicionales, Radar implementa una arquitectura dirigida por eventos basada en streaming de datos asíncrono y colas de procesamiento con deduplicación en tiempo constante O(1). Esto le permite descubrir, mapear y evaluar activos digitales a escala masiva sin bloqueos por latencia de red

# El Pipeline Técnico de Escaneo:

 - Descubrimiento y Enclave de Activos: Ejecuta una fase de enumeración pasiva y activa combinando subfinder y assetfinder para mapear la totalidad de subdominios asociados al objetivo.

 -  Mapeo de Infraestructura y Enrutamiento: Extrae registros DNS mediante dnsx e intercepta el ASN (Autonomous System Number). El análisis del ASN permite identificar de forma precisa la propiedad física de la red para clasificar la infraestructura en entornos Cloud, Self-Hosted o Reseller, detectando la presencia o ausencia de CDNs (filtros de mitigación).

 -  Telemetría Web y Atribución: Utiliza httpx y consultas whois para determinar la legitimidad del activo, datos de registro de dominio, códigos de estado HTTP y disponibilidad de cabeceras de seguridad.

 - Fingerprinting Cruzado y Escaneo de Puertos: Realiza una inspección de puertos sobre los 100 vectores más comunes mediante nmap correlacionando los resultados con la identificación de tecnologías y versiones web provistas por whatweb. El core del sistema aplica una validación cruzada entre la telemetría de red (fase DNS) y la capa de aplicación (fase web) para eliminar falsos positivos.

 -  Ponderación de Riesgo Dinámica (Scoring): Todos los hallazgos son procesados por un motor de scoring que clasifica los activos en Tiers de Criticidad (Impacto Alto, Medio y Bajo) basándose en la exposición de datos y obsolescencia del stack tecnológico, centralizando el histórico de deltas en una base de datos local para su posterior visualización.


## Opción 1_ Clona el repo:
```git clone https://github.com/Chmod351/radar```

Construir la Imagen

Desde la raíz del proyecto, ejecutá:

```docker build -t radar .```


## Opción 2_ Descargar la Imagen (Recomendado)

`docker pull chmod351/radar:latest`

#   Despliegue con Docker

El proyecto se encuentra empaquetado y disponible en Docker Hub sobre una base de Kali Linux con todas las herramientas de reconocimiento (`subfinder`, `nmap`, `httpx`, etc.) y el runtime de `Bun` preinstalados.

###   Descargar una de las Imágenes DisponibleS
* `chmod351/radar:latest` - Última versión estable de la rama master.
* `chmod351/radar:1.1.0` - Release específica de producción.

## Uso:

en la carpeta raiz : `bun run radar -S target.com`

## Leer el manual

`bun run radar man`


## Variables

``NODE_ENV``=test ó dev ` guardar informacion local o no y define que se imprime en la consola
`
`IS_DOCKER`  para saber en que entornos guardar la base de datos. Sin esto la base de datos persiste usando como ruta el directorio de ejecucion  
`WEBHOOK_URL`= api del webhook para recibir los eventos del escaneo en tiempo real: 

Recibe 2 tipos de eventos: 

### Fase 1 o 3 terminada:

`` {
  "scanId": 104,
  "status": "completed",
  "total_stages_executed": 3,
  "total_subdomains_found": 42
}``

### Streamings de Datos: 

`` {
  "scanId": 104,
  "status": "process",
  "target": "target.com",
  "ip": "1.1.1.1",
  "open_ports": [
    {
      "port": 443,
      "service": "https",
      "protocol": 6,
      "version": "nginx",
      "transport": 6
    }
  ],
  "http_intel": [
    {
      "protocol": 1,
      "status": 200,
      "security": { "strict-transport-security": true },
      "server": "nginx",
      "poweredBy": null,
      "cookies": true,
      "attempts": [
        {
          "method": "GET",
          "header": null,
          "status": 200,
          "size": 1024,
          "timestamp": "2026-05-28T11:47:00Z"
        }
      ],
      "error": null
    }
  ],
  "webserver": "nginx",
  "total_stages_executed": 3
}``


## Tests:
para correr los test `bun run test`

## Lint:
para correr el linter por todo el proyecto `bun run lint:fix` 

## Radar usa SQLITE para almacenar la informacion
 
consulta el manual para leer las queries que hay disponibles.

## Disclaimer

Esta herramienta fue creada para la gestión de activos y auditoría de seguridad autorizada. El uso en sistemas sin consentimiento es responsabilidad del usuario

