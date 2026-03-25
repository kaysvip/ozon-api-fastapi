from fastapi import APIRouter
from loguru import logger

from app.schemas.ozon_schemas import (
    ApiResponse,
    GetPageDataRequest,
    GetNextPageRequest,
    SearchRequest,
    GetShopPageRequest,
    GetOtherOffersRequest,
    GetStoreCreatedDaysRequest,
    GetSellerDataRequest,
    GetTokenAndFpRequest,
    OzonCaptchaGetTokenAndFpRequest,
    OzonCaptchaGetTokenAndFpData,
)
from services.ozon_client import OzonClient, get_token_and_fp
from services.ozon_captcha.captcha_solver import build_captcha_result

ozon_router = APIRouter(prefix="/api/v1", tags=["Ozon"])


# ============================================================
# /api/v1/ozon_abt — challenge 解析（透传到 challenge 服务）
# ============================================================

@ozon_router.post("/ozon_abt/get_token_and_fp")
def api_get_token_and_fp(req: GetTokenAndFpRequest) -> ApiResponse:
    token, fp = get_token_and_fp(
        req.challenge, req.user_agent, req.unmasked_vendor, req.unmasked_renderer
    )
    if not token and not fp:
        return ApiResponse(code=500, message="获取 token 和 fp 失败")
    return ApiResponse(data={"token": token, "fp": fp})


# ============================================================
# /api/v1/ozon — Ozon 数据接口
# ============================================================

@ozon_router.post("/ozon/get_page_data")
def api_get_page_data(req: GetPageDataRequest) -> ApiResponse:
    client = OzonClient(req.cookies, req.proxy)
    body = client.get_page_data(req.sku)
    if not body:
        return ApiResponse(code=500, message=f"获取页面数据失败: {client.last_error}")
    return ApiResponse(data={"body": body})


@ozon_router.post("/ozon/get_next_page")
def api_get_next_page(req: GetNextPageRequest) -> ApiResponse:
    client = OzonClient(req.cookies, req.proxy)
    body = client.get_next_page(req.uri)
    if not body:
        return ApiResponse(code=500, message=f"获取下一页数据失败: {client.last_error}")
    return ApiResponse(data={"body": body})


@ozon_router.post("/ozon/search")
def api_search(req: SearchRequest) -> ApiResponse:
    client = OzonClient(req.cookies, req.proxy)
    html = client.search(req.search_text)
    if not html:
        return ApiResponse(code=500, message=f"搜索失败: {client.last_error}")
    return ApiResponse(data={"html": html})


@ozon_router.post("/ozon/get_shop_page")
def api_get_shop_page(req: GetShopPageRequest) -> ApiResponse:
    client = OzonClient(req.cookies, req.proxy)
    html = client.get_shop_page(req.shop_url)
    if not html:
        return ApiResponse(code=500, message=f"获取店铺页面失败: {client.last_error}")
    return ApiResponse(data={"html": html})


@ozon_router.post("/ozon/get_other_offers")
def api_get_other_offers(req: GetOtherOffersRequest) -> ApiResponse:
    client = OzonClient(req.cookies, req.proxy)
    body = client.get_other_offers(req.sku)
    if not body:
        return ApiResponse(code=500, message=f"获取跟卖信息失败: {client.last_error}")
    return ApiResponse(data={"body": body})


@ozon_router.post("/ozon/get_store_created_days")
def api_get_store_created_days(req: GetStoreCreatedDaysRequest) -> ApiResponse:
    client = OzonClient(req.cookies, req.proxy)
    body = client.get_store_created_days(req.seller_id)
    if not body:
        return ApiResponse(code=500, message=f"获取店铺天数失败: {client.last_error}")
    return ApiResponse(data={"body": body})


@ozon_router.post("/ozon/get_seller_data")
def api_get_seller_data(req: GetSellerDataRequest) -> ApiResponse:
    client = OzonClient(req.cookies, req.proxy)
    body = client.get_seller_data(req.company_id, req.sku)
    if not body:
        return ApiResponse(code=500, message=f"获取卖家数据失败: {client.last_error}")
    return ApiResponse(data={"body": body})


# ============================================================
# /api/v1/ozon/captcha — 滑块验证码处理
# ============================================================

@ozon_router.post("/ozon/captcha/get_token_and_fp")
def captcha_get_token_and_fp(req: OzonCaptchaGetTokenAndFpRequest) -> ApiResponse:
    """
    传入 captcha-input 的 value，返回提交到 /abt/captcha/result 所需的 token 和 fp。
    """
    try:
        result = build_captcha_result(
            captcha_input=req.captcha_input,
            user_agent=req.user_agent,
        )
        data = OzonCaptchaGetTokenAndFpData(
            token=result['token'],
            fp=result['fp'],
            slider_x=result['slider_x'],
            slider_y=result['slider_y'],
        )
        return ApiResponse(code=200, message="获取成功", data=data.model_dump())
    except Exception as e:
        logger.exception("captcha get_token_and_fp 失败")
        return ApiResponse(code=500, message=str(e), data=None)
