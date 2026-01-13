
# CyberGuard – Intelligent Web Application Firewall

CyberGuard is a FastAPI-based intelligent firewall system designed for real-time
web attack detection, visualization, and automated response.

<img width="1898" height="915" alt="Screenshot 2025-11-19 193159" src="https://github.com/user-attachments/assets/6bfc9144-9b09-41bb-9b60-e3d321e7840d" />
Dashboard page

<img width="1246" height="873" alt="severity" src="https://github.com/user-attachments/assets/5c273150-a7ae-4d51-9686-1ebb414c74f6" />
Severity page

<img width="1237" height="880" alt="geomap" src="https://github.com/user-attachments/assets/82e4b7a8-a2d5-4b31-a6c2-2e4d2eddfe99" />
attacks on map

<img width="593" height="884" alt="tree1" src="https://github.com/user-attachments/assets/0b19b7a8-beca-474a-b3c3-e3e07cbe544c" />

project structure 
____________________________________________

Check out all outputs inside Output folders.

_____________________________________________

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

ssh -p 2222 omburande@127.0.0.1
sudo ip route del default via 192.168.1.1 dev enp0s3
ping -c 3 google.com

Access dashboard at:
http://localhost:8000/dashboard
http://localhost:8000/simulate

Server Ip:- 192.168.1.50
