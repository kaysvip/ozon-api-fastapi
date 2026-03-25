"""
ozon-api-fastapi — Ozon 数据采集 FastAPI 后端
"""

import uvicorn

from app import creat_app
from app.config import settings

app = creat_app()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=settings.port, reload=True)
