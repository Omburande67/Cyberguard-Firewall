import requests
import time
import random

# Replace with your computer's IP address from Step 2
YOUR_IP = "192.168.1.50"  # CHANGE THIS TO YOUR ACTUAL IP

BASE_URL = f"http://192.168.1.50:8001"

attacks = [
    {
        "source_ip": f"192.168.1.{random.randint(100, 200)}",
        "path": "/admin/login",
        "payload": "' OR '1'='1' --",
        "severity": "high"
    },
    {
        "source_ip": f"10.0.0.{random.randint(1, 50)}",
        "path": "/search",
        "payload": "<script>alert('XSS')</script>",
        "severity": "high"
    },
    {
        "source_ip": f"172.16.1.{random.randint(1, 100)}",
        "path": "/api/execute",
        "payload": "; ls -la /etc/passwd",
        "severity": "high"
    },
    {
        "source_ip": f"192.168.2.{random.randint(1, 50)}",
        "path": "/download",
        "payload": "../../../etc/passwd",
        "severity": "high"
    }
]

def send_demo_attacks():
    print("🚀 Starting CyberGuard Firewall Demo...")
    print(f"📱 On your phone, go to: {BASE_URL}/dashboard")
    print("=" * 50)

    for i, attack in enumerate(attacks, 1):
        try:
            print(f"Sending attack {i} from {attack['source_ip']}...")
            response = requests.post(f"{BASE_URL}/attack", json=attack, timeout=5)

            if response.status_code == 200:
                data = response.json()
                patterns = data['attack'].get('detected_patterns', ['Normal'])
                print(f"✅ SUCCESS! Detected: {patterns[0]}")
                print(f"   Severity: {data['attack']['severity'].upper()}")
            else:
                print(f"❌ Failed with status: {response.status_code}")

        except Exception as e:
            print(f"❌ Error: {e}")

        print("-" * 30)
        time.sleep(3)  # Wait 3 seconds between attacks

    print("🎉 Demo complete! Check your phone dashboard.")
    print(f"📊 Dashboard: {BASE_URL}/dashboard")
    print(f"🎮 Simulator: {BASE_URL}/simulate")

if __name__ == "__main__":
    send_demo_attacks()
