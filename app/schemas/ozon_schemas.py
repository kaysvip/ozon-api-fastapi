from typing import Optional, Any

from pydantic import BaseModel, Field


# ─── 通用响应格式 ───

class ApiResponse(BaseModel):
    code: int = 200
    message: str = "ok"
    data: Any = None


# ─── Ozon 数据接口请求体 ───

class GetPageDataRequest(BaseModel):
    sku: str
    cookies: str = ""
    proxy: str = ""


class GetNextPageRequest(BaseModel):
    uri: str = ""
    cookies: str = ""
    proxy: str = ""


class SearchRequest(BaseModel):
    search_text: str
    cookies: str = ""
    proxy: str = ""


class GetShopPageRequest(BaseModel):
    shop_url: str
    cookies: str = ""
    proxy: str = ""


class GetOtherOffersRequest(BaseModel):
    sku: str
    cookies: str = ""
    proxy: str = ""


class GetStoreCreatedDaysRequest(BaseModel):
    seller_id: str
    cookies: str = ""
    proxy: str = ""


class GetSellerDataRequest(BaseModel):
    company_id: str
    sku: str
    cookies: str = ""
    proxy: str = ""


class GetTokenAndFpRequest(BaseModel):
    challenge: str
    user_agent: str = ""
    unmasked_vendor: str = ""
    unmasked_renderer: str = ""


# ─── 滑块验证码 captcha-input 处理 ───

class OzonCaptchaGetTokenAndFpRequest(BaseModel):
    captcha_input: str = Field(..., description="页面中 captcha-input 的 value")
    user_agent: Optional[str] = Field(None, description="User-Agent (不传使用默认值)")


class OzonCaptchaGetTokenAndFpData(BaseModel):
    token: str = Field(..., description="加密后的 token")
    fp: str = Field(..., description="加密后的 fp")
    slider_x: float = Field(..., description="识别出的滑块 x 偏移")
    slider_y: int = Field(..., description="滑块固定 y")
