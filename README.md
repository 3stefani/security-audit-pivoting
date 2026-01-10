# 🌐 Language / Idioma

[![en](https://img.shields.io/badge/lang-English-blue.svg)](README.en.md)
[![es](https://img.shields.io/badge/lang-Español-red.svg)](README.md)

---

# Auditoría de Seguridad - Pentesting Web y Pivoting de Red

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-blue)](https://owasp.org/Top10/)
[![Metasploit](https://img.shields.io/badge/Metasploit-Framework-red)](https://www.metasploit.com/)

## Descripción del Proyecto

Proyecto de demostración de auditoría de seguridad integral que incluye pentesting de aplicación web y técnicas avanzadas de pivoting para acceso a redes internas. El proyecto simula un escenario real de ataque multi-fase contra una infraestructura segmentada.

**⚠️ Este proyecto es únicamente con fines educativos y debe ejecutarse solo en entornos controlados con autorización explícita.**

## Objetivos

- Demostrar vulnerabilidades comunes del **OWASP Top 10 2021**
- Ilustrar técnicas de **movimiento lateral** mediante pivoting
- Documentar **metodología profesional** de pentesting
- Proporcionar **evidencias** de explotación y remediación

## Arquitectura del Laboratorio
```
┌─────────────────┐
│   Kali Linux    │ 192.168.0.30
│   (Atacante)    │
└────────┬────────┘
         │ Red Bridge
         │
┌────────▼────────────────┐
│ Ubuntu Mutillidae       │
│ DMZ:  192.168.0.21      │
│ INT:  192.168.8.131     │
│ (Servidor Web)          │
└────────┬────────────────┘
         │ Red Host-Only
         │
┌────────▼────────────────┐
│  Metasploitable         │
│  192.168.8.133          │
│  (Servidor Interno)     │
└─────────────────────────┘
```

### Especificaciones Técnicas

| Máquina | Sistema Operativo | Interfaces | IP |
|---------|-------------------|------------|-----|
| **Kali Linux** | Kali Linux 2024.x | eth0 | 192.168.0.30 |
| **Ubuntu Mutillidae** | Ubuntu Server 20.04 | ens33 (Bridge)<br>ens37 (Host-Only) | 192.168.0.21<br>192.168.8.131 |
| **Metasploitable** | Ubuntu 8.04 (Metasploitable 2) | eth0 (Host-Only) | 192.168.8.133 |

## Herramientas Utilizadas

### Reconocimiento y Análisis
-  **Burp Suite Community** - Proxy interceptor y análisis web
-  **Skipfish** - Web application security scanner
-  **Nmap** - Network mapper y port scanner

### Explotación
-  **Metasploit Framework** - Plataforma de explotación
-  **Meterpreter** - Payload avanzado para post-explotación
-  **SQLMap** - Herramienta automatizada de SQL Injection (opcional)

### Post-Explotación
-  **John the Ripper** - Password cracker
-  **Python** - Scripting y servidor HTTP
-  **Hashcat** - Advanced password recovery

## Vulnerabilidades Identificadas

### 🔴 Críticas (CVSS 9.0-10.0)

| Vulnerabilidad | CVSS | Impacto |
|----------------|------|---------|
| **SQL Injection** | 9.8 | Extracción de BD completa, bypass autenticación |
| **Remote Code Execution** | 10.0 | Control total del servidor web |
| **Samba Exploit (Pivoting)** | 9.6 | Acceso root a red interna |

### 🟠 Altas (CVSS 7.0-8.9)

| Vulnerabilidad | CVSS | Impacto |
|----------------|------|---------|
| **Path Traversal** | 7.5 | Lectura de archivos sensibles |
| **Broken Authentication** | 8.1 | Fuerza bruta sin restricciones |

### 🟡 Medias (CVSS 4.0-6.9)

| Vulnerabilidad | CVSS | Impacto |
|----------------|------|---------|
| **Security Misconfiguration** | 5.3 | Divulgación de información |
| **Cryptographic Failures** | 6.5 | Contraseñas en texto plano |

## Cadena de Ataque Completa
```
┌─────────────────────────────────────────────────────────┐
│                  FASE 1: RECONOCIMIENTO                  │
├─────────────────────────────────────────────────────────┤
│ • Burp Suite → Mapeo de aplicación web                  │
│ • Skipfish → Escaneo automatizado                       │
│ • Identificación de vectores de ataque                  │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│               FASE 2: EXPLOTACIÓN WEB                    │
├─────────────────────────────────────────────────────────┤
│ • SQL Injection → 26 usuarios comprometidos             │
│ • Webshell Upload → RCE como www-data                   │
│ • Path Traversal → Lectura de /etc/passwd               │
│ • Burp Intruder → Fuerza bruta de credenciales          │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│             FASE 3: POST-EXPLOTACIÓN                     │
├─────────────────────────────────────────────────────────┤
│ • ip addr show → Descubrimiento red 192.168.8.0/24      │
│ • ping sweep → Host 192.168.8.133 identificado          │
│ • Persistencia → Usuario SSH creado                     │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│                  FASE 4: PIVOTING                        │
├─────────────────────────────────────────────────────────┤
│ • msfvenom → Payload Meterpreter generado               │
│ • Sesión Meterpreter establecida                        │
│ • autoroute → Túnel a red interna configurado           │
│ • Port scan → Servicios vulnerables identificados       │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│           FASE 5: EXPLOTACIÓN RED INTERNA                │
├─────────────────────────────────────────────────────────┤
│ • Samba usermap_script (CVE-2007-2447)                  │
│ • Shell root obtenida                                   │
│ • /etc/shadow extraído                                  │
└────────────────────┬────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────┐
│         FASE 6: POST-EXPLOTACIÓN AVANZADA                │
├─────────────────────────────────────────────────────────┤
│ • John the Ripper → 3 contraseñas crackeadas            │
│ • Enumeración completa del sistema                      │
│ • Documentación de acceso root                          │
└─────────────────────────────────────────────────────────┘
```

## Estructura del Repositorio
```
pentesting-web-pivoting/
│
├── README.md                          # Este archivo (Español)
├── README.en.md                       # English version
├── LICENSE                            # Licencia MIT
│
├── documentacion/
│   ├── informe-ejecutivo.md          # Informe completo en español
│   ├── executive-report.en.md        # Full report in English
│   ├── metodologia.md                # Metodología detallada
│   └── recomendaciones.md            # Guía de remediación
│
├── evidencias/
│   ├── screenshots/
│   │   ├── 01-burp-sitemap.png
│   │   ├── 02-sqli-extraction.png
│   │   ├── 03-webshell-rce.png
│   │   ├── 04-network-discovery.png
│   │   ├── 05-meterpreter-session.png
│   │   ├── 06-pivoting-autoroute.png
│   │   ├── 07-samba-exploit.png
│   │   └── 08-root-access.png
│   │
│   └── logs/
│       ├── burp-http-history.txt
│       ├── nmap-scans.txt
│       ├── metasploit-output.txt
│       └── john-cracking-results.txt
│
├── scripts/
│   ├── webshell.php                  # Webshell utilizada
│   ├── payload-generator.sh          # Script de generación de payloads
│   └── scan-automation.py            # Automatización de escaneos
│
└── recursos/
    ├── setup-lab.md                  # Guía de montaje del laboratorio
    ├── comandos-utilizados.md        # Lista completa de comandos
    └── referencias.md                # Enlaces y recursos adicionales
```

## Credenciales Comprometidas

### Servidor Web (Mutillidae) - SQL Injection

**Total: 26 usuarios con contraseñas en texto plano**
```
admin:admin
john:monkey
jeremy:password
bryce:password
ed:pentest
samurai:samurai
jim:password
pablo:letmein
dave:password
adrian:somepassword
[... +16 usuarios adicionales]
```

### Servidor Interno (Metasploitable) - Password Cracking

**Hashes MD5 crackeados con John the Ripper:**
```
✅ klog:123456789
✅ sys:batman
✅ service:service

❌ root: No crackeado (no en rockyou.txt)
❌ msfadmin: No crackeado
❌ user: No crackeado
❌ postgres: No crackeado
```

## 📈 Resultados Clave

| Métrica | Resultado |
|---------|-----------|
| **Vulnerabilidades Críticas** | 3 |
| **Vulnerabilidades Altas** | 2 |
| **Vulnerabilidades Medias** | 2 |
| **Usuarios Comprometidos** | 26 |
| **Contraseñas Crackeadas** | 3 |
| **Sistemas Comprometidos** | 2/2 (100%) |
| **Acceso Root Obtenido** | ✅ Sí |
| **Tiempo Total de Ataque** | ~4 horas |

### Impacto por Fase
```
Fase 1 (Recon):           [████░░░░░░] 40% de información obtenida
Fase 2 (Explotación Web): [██████████] 100% servidor web comprometido
Fase 3 (Post-Exp):        [████████░░] 80% red interna descubierta
Fase 4 (Pivoting):        [██████████] 100% túnel establecido
Fase 5 (Red Interna):     [██████████] 100% servidor interno comprometido
Fase 6 (Post-Exp Avz):    [███████░░░] 70% credenciales extraídas
```

## 🛡️ Recomendaciones de Remediación

### 🔴 Prioridad CRÍTICA (0-7 días)

1. **Implementar Prepared Statements**
```php
// ❌ VULNERABLE
$query = "SELECT * FROM users WHERE username='$username'";

// ✅ SEGURO
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
```

2. **Parchear Samba** (CVE-2007-2447)
```bash
sudo apt-get update && sudo apt-get upgrade samba
```

3. **Segmentar red con firewall**
```bash
# Bloquear tráfico DMZ → Red Interna por defecto
iptables -A FORWARD -i ens33 -o ens37 -j DROP
# Permitir solo tráfico específico autorizado
iptables -A FORWARD -i ens33 -o ens37 -p tcp --dport 443 -j ACCEPT
```

### 🟠 Prioridad ALTA (1-4 semanas)

4. **Implementar WAF**
   - ModSecurity + OWASP Core Rule Set
   - Cloudflare / AWS WAF

5. **Rate Limiting y CAPTCHA**
```php
if ($failed_attempts >= 3) {
    require_captcha();
}
```

6. **Hashear contraseñas**
```php
$hashed = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
```

### 🟡 Prioridad MEDIA (1-3 meses)

7. **Implementar IDS/IPS** (Snort, Suricata)
8. **SIEM** para correlación de eventos
9. **Capacitación en Secure Coding**
10. **Pentesting regular** (trimestral/anual)

## Lecciones Aprendidas

### 1️⃣ Una vulnerabilidad = Compromiso total

**SQL Injection** → **Webshell** → **Pivoting** → **Red interna comprometida**

La cadena de ataque demostró que una sola vulnerabilidad inicial puede escalar hasta el compromiso completo de la infraestructura.

### 2️⃣ La segmentación sin firewall es inútil

Separar redes (DMZ / Interna) **no es suficiente** sin controles de firewall activos. Un atacante con acceso a la DMZ puede alcanzar fácilmente la red interna.

### 3️⃣ la defensa en profundidad es esencial

Múltiples capas de seguridad:
- ✔️ Validación de entrada (Prepared Statements)
- ✔️ WAF
- ✔️ Firewall de red
- ✔️ IDS/IPS
- ✔️ Monitoreo activo
- ✔️ Respuesta a incidentes

### 4️⃣ La detección es tan importante como la prevención

Sin monitoreo activo, todo el ataque pasó **completamente desapercibido**. Un SOC con alertas configuradas habría detectado:
- Múltiples errores SQL
- Creación de archivos PHP en directorio web
- Tráfico anómalo hacia red interna
- Conexiones Meterpreter

## Cómo Reproducir este Lab

### Prerrequisitos

- VMware Workstation / VirtualBox
- 16GB RAM mínimo
- 100GB espacio en disco
- Conocimientos básicos de redes y Linux

### Instalación

1. **Descargar imágenes:**
   - [Kali Linux](https://www.kali.org/get-kali/)
   - [Metasploitable 2](https://sourceforge.net/projects/metasploitable/)
   - Ubuntu Server 20.04 + [Mutillidae](https://github.com/webpwnized/mutillidae)

2. **Configurar redes:**
```
Kali:       eth0 → Bridge
Ubuntu:     ens33 → Bridge
            ens37 → Host-Only (VMnet1)
Metasploit: eth0 → Host-Only (VMnet1)
```

3. **Seguir guía detallada:** [setup-lab.md](recursos/setup-lab.md)

## 📚 Referencias y Recursos

### Documentación Oficial
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)

### CVEs Explotados
- [CVE-2007-2447](https://nvd.nist.gov/vuln/detail/CVE-2007-2447) - Samba usermap script

### Herramientas
- [CVSS Calculator 4.0](https://www.first.org/cvss/calculator/4.0)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [MITRE ATT&CK](https://attack.mitre.org/)


## 👤 Autor

**Estefanía Ramírez Martínez**

Pentester Junior | eJPT Certified | Cybersecurity Enthusiast

- Email: estefania.rammar@gmail.com
- LinkedIn: [linkedin.com/in/estefania-ramirez-martinez](https://linkedin.com/in/estefaniazerimar/)
- GitHub: [@estefaniaramirez](https://github.com/3stefani)
- Blog: [diariohacking.com](https://diariohacking.com)
- Certificaciones: eJPT (Junior Penetration Tester)

## Contribuciones

Las contribuciones son bienvenidas. Si encuentras algún error o quieres mejorar la documentación:

1. Fork el proyecto
2. Crea una rama (`git checkout -b feature/mejora`)
3. Commit tus cambios (`git commit -m 'Añadir mejora'`)
4. Push a la rama (`git push origin feature/mejora`)
5. Abre un Pull Request

## Licencia

Este proyecto está bajo la Licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.
```
MIT License

Copyright (c) 2025 Estefanía Ramírez Martínez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

## ⚠️ Disclaimer Legal

**IMPORTANTE: Este proyecto es únicamente con fines educativos y de investigación en seguridad.**

- ✅ **Permitido:** Uso en entornos controlados y laboratorios personales
- ✅ **Permitido:** Pentesting con autorización explícita por escrito
- ❌ **Prohibido:** Uso contra sistemas sin autorización
- ❌ **Prohibido:** Actividades ilegales o maliciosas

El autor **NO se hace responsable** del mal uso de la información o herramientas presentadas en este repositorio. El acceso no autorizado a sistemas informáticos es **ilegal** en la mayoría de jurisdicciones y puede resultar en:

- Penas de prisión
- Multas económicas
- Antecedentes penales
- Demandas civiles

**Actúa siempre de forma ética y legal. #EthicalHacking**

---

## 🌟 Agradecimientos

- **OWASP** por proporcionar recursos invaluables de seguridad web
- **Metasploit Team** por la excelente plataforma de pentesting
- **Mutillidae Project** por la aplicación vulnerable educativa
- **Offensive Security** por la metodología de pentesting
- **Comunidad InfoSec** por compartir conocimiento libremente

---


---

*Última actualización: Enero 2026*
