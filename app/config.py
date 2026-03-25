from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # 服务端口
    port: int = 62002

    # challenge 解析服务地址（get_token_and_fp，gin 服务）
    challenge_host: str = "https://ozon-crawl-gin.a0bc.com"

    model_config = {"env_prefix": "OZON_"}


settings = Settings()
