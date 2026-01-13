import redis
import json
import os

r = redis.Redis(host=os.getenv("REDIS_HOST"), port=6379)

def publish_attack(event: dict):
    r.publish("attacks", json.dumps(event))
