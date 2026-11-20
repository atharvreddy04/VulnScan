import asyncio
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.routers import dashboard, dirs, network, recon, ssl, testing, vulnerabilities, web

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

Base.metadata.create_all(bind=engine)

app = FastAPI(title="VulnScan Security Assessment API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(dashboard.router)
app.include_router(network.router)
app.include_router(web.router)
app.include_router(ssl.router)
app.include_router(vulnerabilities.router)
app.include_router(recon.router)
app.include_router(dirs.router)
app.include_router(testing.router)


@app.get("/api/health")
def health_check():
    return {"status": "ok", "platform": "VulnScan"}