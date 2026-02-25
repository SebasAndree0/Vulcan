🛡️ Vulcan – Vulnerability Scanner

Vulcan es una herramienta fullstack de análisis de seguridad web que permite evaluar configuraciones críticas de un sitio, detectar vulnerabilidades comunes y generar un puntaje de riesgo junto a un reporte detallado.

🚀 Características

🔍 Escaneo de sitios web en tiempo real

🔐 Validación de HTTPS y redirecciones

🛡️ Análisis de cabeceras de seguridad:

Content-Security-Policy (CSP)

X-Frame-Options

X-Content-Type-Options

Strict-Transport-Security (HSTS)

📊 Cálculo de score de vulnerabilidad

📄 Reporte detallado de riesgos detectados

💻 Dashboard web para visualización de resultados

🏗️ Arquitectura

El proyecto está dividido en dos partes:

vulnscan-api → Backend encargado del análisis de seguridad

vulnscan-web → Frontend para visualización de resultados

Vulcan/
├── vulnscan-api/
└── vulnscan-web/
🧰 Tecnologías
Backend

Node.js

TypeScript

REST API

Frontend

Angular (o framework frontend usado)

TypeScript

HTML / CSS

⚙️ Instalación y ejecución
1. Clonar el repositorio
git clone https://github.com/SebasAndree0/Vulcan.git
cd Vulcan
2. Backend (API)
cd vulnscan-api
npm install
npm run dev

La API estará disponible en:

http://localhost:3000
3. Frontend (Web)
cd vulnscan-web
npm install
npm start

La aplicación web estará en:

http://localhost:4200
🔎 Ejemplo de uso

Ingresar una URL en el sistema

Ejecutar el escaneo

Revisar:

Estado HTTPS

Cabeceras de seguridad

Puntaje de riesgo

Vulnerabilidades detectadas

📊 Ejemplo de resultado
URL: https://example.com
HTTPS: ✅
HSTS: ❌
CSP: ❌
X-Frame-Options: ❌

VulnScore: 25% (Riesgoso)
🎯 Objetivo del proyecto

Este proyecto fue desarrollado como parte de aprendizaje en ciberseguridad y desarrollo fullstack, enfocado en:

Análisis de seguridad web

Buenas prácticas de configuración HTTP

Arquitectura API + Cliente

Evaluación automatizada de vulnerabilidades

🚧 Mejoras futuras

Escaneo de puertos y servicios

Integración con bases de datos

Historial de escaneos

Exportación de reportes (PDF/JSON)

Autenticación de usuarios

👨‍💻 Autor

Sebastián Brenet
GitHub: https://github.com/SebasAndree0

📄 Licencia

Este proyecto está bajo la licencia MIT.
