import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import db_manager
from app.sniffer.capture import capture_engine
from app.analytics.features import feature_extractor
from app.analytics.heuristics import heuristic_detector
from app.analytics.ml_detector import ml_detector
from app.api.routes import router as api_router
from app.api.websocket import ws_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("wifi_monitor.main")

# Background asyncio loop reference for thread-safe websocket broadcasts
main_loop: asyncio.AbstractEventLoop = None

def packet_processing_pipeline(packet: dict):
    """
    Core defensive pipeline:
    Inbound Packet -> Feature Extractor -> Heuristics -> ML Isolation Forest -> Broadcast
    """
    src_ip = packet.get("src_ip")
    if not src_ip:
        return

    # 1. Update sliding window
    feature_extractor.add_packet(packet)
    features = feature_extractor.extract_features_for_ip(src_ip)

    # 2. Rule-based heuristic detection (port scan, spike, rogue device)
    alert = heuristic_detector.check_heuristics(src_ip, features, packet)

    # 3. Machine Learning Anomaly Detection (Isolation Forest)
    anomaly = ml_detector.score_features(src_ip, features)

    # 4. Stream to Web UI via WebSocket (thread-safe scheduling)
    if main_loop and main_loop.is_running():
        # Broadcast packet log
        asyncio.run_coroutine_threadsafe(
            ws_manager.broadcast({
                "type": "packet",
                "data": packet,
                "rates": capture_engine.get_stats()
            }),
            main_loop
        )

        if alert:
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast({
                    "type": "alert",
                    "data": alert
                }),
                main_loop
            )

        if anomaly:
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast({
                    "type": "anomaly",
                    "data": anomaly
                }),
                main_loop
            )

@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()
    
    logger.info("Initializing Database...")
    db_manager.connect()

    logger.info("Registering Packet Pipeline...")
    capture_engine.register_pipeline_callback(packet_processing_pipeline)

    logger.info("Starting Capture Engine...")
    capture_engine.start()

    yield

    logger.info("Shutting down Capture Engine and Database...")
    capture_engine.stop()
    db_manager.close()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan
)

# Enable CORS for local Vite development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.API_PREFIX)

@app.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep-alive receive ping
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
