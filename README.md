# CyberGuard – Intelligent Web Application Firewall

CyberGuard is a FastAPI-based intelligent firewall system designed for real-time
web attack detection, visualization, and automated response.

## Features
- Live attack monitoring using WebSockets
- Regex-based threat detection (SQLi, XSS, Command Injection, etc.)
- GeoIP-based attack visualization with world heatmap
- Automated IP blocking and rule management
- Severity classification and attack pattern analytics

## Tech Stack
- FastAPI (Python)
- WebSockets
- Docker & Docker Compose
- HTML, CSS, JavaScript (Dashboard)
- GeoIP API integration

## How to Run
```bash
docker-compose up -d --build

Access dashboard at:
http://localhost:8000/dashboard
http://localhost:8000/simulate

Server Ip:- 192.168.1.50
