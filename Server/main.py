from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os

app = FastAPI()

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# -----------------------------
#  DATA MODEL
# -----------------------------
class Attack(BaseModel):
    source_ip: str
    path: str
    payload: str
    severity: str

# In-memory attack storage
ATTACKS = []

# -----------------------------
#  WEBSOCKET MANAGER
# -----------------------------
class ConnectionManager:
    def __init__(self):
        self.active = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active.append(websocket)

    async def broadcast(self, data):
        """Send JSON to all connected dashboards"""
        for ws in self.active:
            await ws.send_json(data)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active:
            self.active.remove(websocket)

manager = ConnectionManager()

# -----------------------------
#  API ROUTES
# -----------------------------

@app.get("/")
def root():
    return FileResponse("index.html")

@app.get("/simulate")
def simulate_ui():
    return FileResponse("simulate.html")

# === Receive attack event ===
@app.post("/attack")
async def receive_attack(a: Attack):
    data = a.dict()
    ATTACKS.append(data)
    await manager.broadcast(data)
    return {"received": True, "attack": data}

# === Get list of ALL attacks ===
@app.get("/attacks")
def get_attacks():
    return {"attacks": ATTACKS}

# === WebSocket endpoint ===
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
