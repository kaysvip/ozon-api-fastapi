from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # 服务端口
    port: int = 62002

    # challenge 解析服务地址（get_token_and_fp，gin 服务）。
    # 仅在本地求解关闭或失败时作为回退使用。
    challenge_host: str = "https://ozon-crawl-gin.a0bc.com"

    # 是否在本地求解 403 JS challenge（不依赖外部 gin 服务）
    local_challenge: bool = True

    # 本地求解失败时是否回退到 challenge_host
    challenge_remote_fallback: bool = True

    # 指纹档案池大小。池子越大指纹越分散，但首次填满要多调几次指纹服务。
    profile_pool_size: int = 8

    model_config = {"env_prefix": "OZON_"}


settings = Settings()
