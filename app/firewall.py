from .detector import publish_attack
import requests

def detect_attack(data):

    # Geo lookup using ip-api.com (free)
    try:
        geo = requests.get(
            f"http://ip-api.com/json/{data.source_ip}?fields=status,country,regionName,city,isp,org,query"
        ).json()

        if geo.get("status") == "success":
            geo_info = {
                "ip": geo.get("query"),
                "country": geo.get("country"),
                "region": geo.get("regionName"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "org": geo.get("org"),
            }
        else:
            geo_info = None

    except:
        geo_info = None

    # Build event
    event = {
        "source_ip": data.source_ip,
        "path": data.path,
        "payload": data.payload,
        "severity": data.severity,
        "geo": geo_info
    }

    publish_attack(event)
    return event
