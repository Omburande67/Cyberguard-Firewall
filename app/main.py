from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
import os
import httpx
import random
import re
from datetime import datetime, timedelta
from typing import Dict, List, Set
import json

app = FastAPI()

app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")

# -----------------------------
#  FIREWALL CONFIGURATION
# -----------------------------
FIREWALL_CONFIG = {
    "blocked_ips": set(),
    "suspicious_paths": ["/admin", "/phpmyadmin", "/wp-admin", "/shell", "/cmd", "/backend"],
    "rate_limits": {},
    "auto_block_threshold": 3,
    "max_payload_size": 1000
}

# -----------------------------
#  DATA MODELS
# -----------------------------
class Attack(BaseModel):
    source_ip: str
    path: str
    payload: str
    severity: str

class FirewallRule(BaseModel):
    rule_type: str
    value: str
    description: str

# Storage
ATTACKS = []
FIREWALL_RULES = []
BLOCKED_IPS: Set[str] = set()

# -----------------------------
#  FIREWALL CORE ENGINE - FIXED
# -----------------------------
class FirewallEngine:
    def __init__(self):
        self.attack_patterns = {
            "SQL Injection": [
                r"union.*select", r"select.*from", r"or.*1=1", r"';.*--",
                r"drop.*table", r"insert.*into", r"update.*set", r"exec.*\(\)",
                r"waitfor.*delay", r"sleep\s*\(\s*\d+\s*\)", r"benchmark\(",
                r"1=1", r"' OR '", r"';", r"--", r"#", r"null", r"having.*1=1",
                r"union.*all", r"information_schema", r"pg_sleep", r"dbms_"
            ],
            "XSS Attack": [
                r"<script", r"javascript:", r"onerror=", r"onload=", r"onclick=",
                r"alert\(", r"document\.cookie", r"<iframe", r"<img.*src=",
                r"eval\(", r"setTimeout\(", r"<svg", r"onmouseover=", r"onfocus=",
                r"<body.*onload", r"<input.*onfocus", r"window\.location",
                r"document\.write", r"innerHTML", r"outerHTML"
            ],
            "Path Traversal": [
                r"\.\./", r"\.\.\\", r"etc/passwd", r"win.ini", r"boot.ini",
                r"../../", r"%2e%2e%2f", r"..%2f", r"..%5c", r"\.\.%00",
                r"\.\.%2f", r"\.\.%5c", r"%2e%2e%2f", r"%2e%2e%5c"
            ],
            "Command Injection": [
                r";\s*(ls|dir|cat|type|rm|del|mkdir|chmod)", r"\|\s*(whoami|id|pwd|uname)",
                r"`.*`", r"\$\(.*\)", r"eval\(", r"exec\(", r"system\(",
                r"cmd\.exe", r"powershell", r"bash.*-c", r"nc\.exe", r"wget", r"curl",
                r"ping.*-c", r"nmap", r"traceroute", r"netstat"
            ],
            "Brute Force": [
                r"password=.*admin", r"login=.*admin", r"user=.*admin",
                r"attempt=.*[0-9]{2,}", r"try=.*[0-9]{2,}", r"admin.*admin",
                r"username=.*admin", r"pass=.*admin", r"pwd=.*admin"
            ],
            "File Inclusion": [
                r"include.*\.php", r"require.*\.php", r"include_once",
                r"require_once", r"fopen.*\.php", r"file_get_contents"
            ]
        }

    def analyze_threat(self, attack_data: dict) -> dict:
        """Comprehensive threat analysis with pattern detection"""
        threat_score = 0
        detected_patterns = []
        recommendations = []
        blocked = False

        ip = attack_data['source_ip']
        path = attack_data['path'].lower()
        payload = attack_data['payload'].lower()
        client_severity = attack_data['severity']  # Keep the client's severity choice

        # Check if IP is blocked
        if ip in BLOCKED_IPS:
            return {
                "blocked": True,
                "reason": "IP is in block list",
                "threat_score": 100,
                "detected_patterns": ["Blocked IP"],
                "severity": "high",  # Always high for blocked IPs
                "client_severity": client_severity
            }

        # Pattern detection
        for category, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    threat_score += 25
                    if category not in detected_patterns:
                        detected_patterns.append(category)

        # Suspicious path detection
        suspicious_paths = ["/admin", "/phpmyadmin", "/wp-admin", "/shell", "/cmd",
                           "/backend", "/api", "/config", "/database", "/login"]
        if any(suspicious in path for suspicious in suspicious_paths):
            threat_score += 20
            if "Suspicious Path" not in detected_patterns:
                detected_patterns.append("Suspicious Path")
            recommendations.append("Monitor access to sensitive paths")

        # Payload size analysis
        if len(payload) > 500:
            threat_score += 15
            if "Oversized Payload" not in detected_patterns:
                detected_patterns.append("Oversized Payload")
            recommendations.append("Large payload detected - potential attack")

        # Special keywords that indicate high severity
        high_severity_keywords = [
            "admin", "password", "root", "sudo", "union select", "drop table",
            "<script", "javascript:", "etc/passwd", "win.ini", "cmd.exe",
            "or 1=1", "union all", "information_schema", "benchmark"
        ]
        for keyword in high_severity_keywords:
            if keyword in payload:
                threat_score += 30
                break

        # Rate limiting analysis
        current_time = datetime.now()
        if ip in FIREWALL_CONFIG["rate_limits"]:
            last_time, count = FIREWALL_CONFIG["rate_limits"][ip]
            time_diff = current_time - last_time

            if time_diff < timedelta(minutes=1):
                if count >= 3:
                    threat_score += 30
                    if "Rate Limit Exceeded" not in detected_patterns:
                        detected_patterns.append("Rate Limit Exceeded")
                    recommendations.append("High frequency attacks detected - consider blocking")
                FIREWALL_CONFIG["rate_limits"][ip] = (last_time, count + 1)
            else:
                FIREWALL_CONFIG["rate_limits"][ip] = (current_time, 1)
        else:
            FIREWALL_CONFIG["rate_limits"][ip] = (current_time, 1)

        # Auto-block logic
        attack_count = len([a for a in ATTACKS if a['source_ip'] == ip])
        if attack_count >= FIREWALL_CONFIG["auto_block_threshold"]:
            BLOCKED_IPS.add(ip)
            blocked = True
            threat_score = 100
            recommendations.append(f"Auto-blocked IP {ip} after {attack_count} attacks")

        # 🔥 FIX: Use client severity but adjust based on threat analysis
        final_severity = client_severity

        # Only override if threat analysis suggests higher severity
        if threat_score >= 60:  # Very high threat
            final_severity = "high"
        elif threat_score >= 40 and client_severity == "low":  # Medium threat but client said low
            final_severity = "medium"
        elif blocked:  # Always high if blocked
            final_severity = "high"

        # Default recommendation if none
        if not recommendations:
            if final_severity == "high":
                recommendations.append("🚨 IMMEDIATE ACTION REQUIRED - High threat detected")
            elif final_severity == "medium":
                recommendations.append("⚠️ Monitor closely - Medium threat level")
            else:
                recommendations.append("ℹ️ Low risk - Continue monitoring")

        return {
            "threat_score": threat_score,
            "detected_patterns": detected_patterns,
            "severity": final_severity,  # Use the adjusted severity
            "client_severity": client_severity,  # Keep original for reference
            "recommendations": recommendations,
            "blocked": blocked,
            "attack_count": attack_count + 1
        }

# Initialize firewall
firewall_engine = FirewallEngine()

# -----------------------------
#  WEBSOCKET MANAGER
# -----------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    async def broadcast(self, data: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except:
                self.active_connections.remove(connection)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

manager = ConnectionManager()

# -----------------------------
#  GEO LOOKUP
# -----------------------------
MOCK_GEO_DATA = {
    '192.168.': [40.7128, -74.0060],
    '10.0.': [34.0522, -118.2437],
    '172.16.': [51.5074, -0.1278],
    '192.11.': [52.5200, 13.4050],
    '127.0.0.1': [35.6762, 139.6503],
    'localhost': [35.6762, 139.6503]
}

@app.get("/geoip/{ip}")
async def geo_lookup(ip: str):
    try:
        for prefix, coords in MOCK_GEO_DATA.items():
            if ip.startswith(prefix):
                return {
                    "ip": ip,
                    "latitude": coords[0],
                    "longitude": coords[1],
                    "city": "Mock Location",
                    "country": "Mock Country"
                }

        url = f"https://ipapi.co/{ip}/json/"
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5)
            data = response.json()

        latitude = data.get("latitude")
        longitude = data.get("longitude")

        if latitude is None or longitude is None:
            random.seed(hash(ip) % 1000)
            latitude = random.uniform(-60, 70)
            longitude = random.uniform(-180, 180)

        return {
            "ip": ip,
            "latitude": latitude,
            "longitude": longitude,
            "city": data.get("city", "Unknown"),
            "country": data.get("country_name", "Unknown"),
            "region": data.get("region", "Unknown")
        }

    except Exception as e:
        random.seed(hash(ip) % 1000)
        return {
            "ip": ip,
            "latitude": random.uniform(-60, 70),
            "longitude": random.uniform(-180, 180),
            "city": "Unknown",
            "country": "Unknown",
            "region": "Unknown"
        }

# -----------------------------
#  FIREWALL API ENDPOINTS
# -----------------------------

@app.get("/")
def root():
    return {"status": "CyberGuard Firewall System Running"}

@app.post("/attack")
async def receive_attack(attack: Attack):
    """Receive and analyze attack data - FIXED SEVERITY"""
    data = attack.dict()
    data['timestamp'] = datetime.now().isoformat()
    data['id'] = len(ATTACKS) + 1

    # Firewall threat analysis
    threat_analysis = firewall_engine.analyze_threat(data)

    # 🔥 KEY FIX: Use the client's severity choice as primary
    # Only override if threat analysis suggests it's necessary
    data.update(threat_analysis)

    # Store attack
    ATTACKS.append(data)

    # Broadcast to all connected dashboards
    await manager.broadcast({
        "type": "new_attack",
        "data": data,
        "firewall_stats": get_firewall_stats()
    })

    response = {
        "received": True,
        "attack": data,
        "threat_analysis": threat_analysis
    }

    if threat_analysis["blocked"]:
        response["message"] = f"Attack blocked from {data['source_ip']}"

    return response

@app.get("/attacks")
def get_attacks():
    return {"attacks": ATTACKS[-100:]}

@app.get("/firewall/stats")
def get_firewall_stats():
    total_attacks = len(ATTACKS)
    blocked_attacks = len([a for a in ATTACKS if a.get('blocked', False)])
    high_severity = len([a for a in ATTACKS if a.get('severity') == 'high'])
    medium_severity = len([a for a in ATTACKS if a.get('severity') == 'medium'])

    pattern_stats = {}
    for attack in ATTACKS:
        for pattern in attack.get('detected_patterns', []):
            pattern_stats[pattern] = pattern_stats.get(pattern, 0) + 1

    return {
        "total_attacks": total_attacks,
        "blocked_attacks": blocked_attacks,
        "high_severity_attacks": high_severity,
        "medium_severity_attacks": medium_severity,
        "active_rules": len(FIREWALL_RULES),
        "blocked_ips_count": len(BLOCKED_IPS),
        "threats_blocked_percentage": round((blocked_attacks / total_attacks * 100), 2) if total_attacks > 0 else 0,
        "pattern_statistics": pattern_stats
    }

@app.post("/firewall/block-ip/{ip}")
async def block_ip(ip: str):
    """Manually block an IP"""
    BLOCKED_IPS.add(ip)
    FIREWALL_CONFIG["blocked_ips"].add(ip)
    return {"blocked": True, "ip": ip, "message": f"IP {ip} added to block list"}

@app.post("/firewall/unblock-ip/{ip}")
async def unblock_ip(ip: str):
    """Unblock an IP"""
    if ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)
    if ip in FIREWALL_CONFIG["blocked_ips"]:
        FIREWALL_CONFIG["blocked_ips"].remove(ip)
    return {"unblocked": True, "ip": ip, "message": f"IP {ip} removed from block list"}

@app.get("/firewall/blocked-ips")
async def get_blocked_ips():
    """Get list of blocked IPs"""
    return {"blocked_ips": list(BLOCKED_IPS)}

@app.post("/firewall/rules")
async def add_firewall_rule(rule: FirewallRule):
    FIREWALL_RULES.append(rule.dict())
    return {"added": True, "rule": rule.dict()}

@app.get("/firewall/rules")
async def get_firewall_rules():
    return {"rules": FIREWALL_RULES}

# -----------------------------
#  WEBSOCKET ENDPOINT
# -----------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "initial_stats",
            "firewall_stats": get_firewall_stats()
        })

        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# -----------------------------
#  UI PAGES
# -----------------------------
@app.get("/dashboard")
def dashboard_ui():
    return FileResponse(os.path.join("dashboard", "index.html"))

@app.get("/simulate")
def simulate_ui():
    return FileResponse(os.path.join("dashboard", "simulate.html"))
