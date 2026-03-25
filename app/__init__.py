from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.view.ozon_view import ozon_router


def creat_app():
    app = FastAPI(
        title="Ozon Api",
        description="Ozon 数据采集 FastAPI 后端",
        version="1.0.0",
        redoc_url="/Ozon-redoc",
        docs_url="/Ozon-docs",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(ozon_router)
    return app
