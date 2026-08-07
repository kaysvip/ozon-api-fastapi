from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


def creat_app():
    # 路由在函数内导入：app.view -> services.ozon_client -> app.config 会回到本模块，
    # 放在模块顶层会形成循环导入（先 import services.ozon_client 时就会炸）。
    from app.view.ozon_view import ozon_router

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
