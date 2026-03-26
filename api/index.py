import sys
from pathlib import Path

from fastapi import FastAPI

ROOT = Path(__file__).resolve().parent.parent
BACKEND_PATH = ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

from app.main import app as backend_app


app = FastAPI(title="Vercel API Wrapper")
app.mount("/api", backend_app)
