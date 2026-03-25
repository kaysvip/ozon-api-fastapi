"""
Ozon 滑块验证码识别模块
y 固定 (pp[0])，只需找 x。
关键修正：matchTemplate 返回的是裁剪后形状的位置，需减去 crop_x 得到元素定位。
"""

import cv2
import numpy as np
import os
from loguru import logger


def _imwrite(path, img):
    ext = os.path.splitext(path)[1] or '.png'
    ok, buf = cv2.imencode(ext, img)
    if ok:
        with open(path, 'wb') as f:
            f.write(buf.tobytes())
    return ok


# ─────────────────── 图片加载 ───────────────────

def load_image_from_url(url: str, session=None, proxy: str = None):
    if session is not None:
        resp = session.get(url, timeout=15)
    else:
        import requests as _req
        proxies = {"http": proxy, "https": proxy} if proxy else None
        resp = _req.get(url, timeout=15, proxies=proxies)
    resp.raise_for_status()
    data = np.frombuffer(resp.content, np.uint8)
    img = cv2.imdecode(data, cv2.IMREAD_UNCHANGED)
    if img is None:
        raise ValueError(f"图片读取失败: {url}")
    return img


# ─────────────────── 预处理 ───────────────────

def _ensure_bgr(img):
    if img.ndim == 2:
        return cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
    if img.shape[2] == 4:
        return cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
    return img


def _get_alpha_mask(img):
    if img.ndim == 3 and img.shape[2] == 4:
        alpha = img[:, :, 3]
        _, mask = cv2.threshold(alpha, 10, 255, cv2.THRESH_BINARY)
        return mask
    return None


def crop_by_alpha(img):
    """
    用 alpha 裁剪滑块，返回 (bgr, mask, (crop_x, crop_y, w, h))
    crop_x/crop_y 是裁剪区域在原图中的偏移——后续需要用来修正坐标。
    """
    alpha_mask = _get_alpha_mask(img)
    bgr = _ensure_bgr(img)

    if alpha_mask is not None:
        ref = alpha_mask
    else:
        gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
        _, ref = cv2.threshold(gray, 10, 255, cv2.THRESH_BINARY)

    pts = cv2.findNonZero(ref)
    if pts is None:
        h, w = bgr.shape[:2]
        return bgr, np.ones((h, w), np.uint8) * 255, (0, 0, w, h)

    x, y, w, h = cv2.boundingRect(pts)
    cropped_bgr = bgr[y:y+h, x:x+w]
    cropped_mask = alpha_mask[y:y+h, x:x+w] if alpha_mask is not None else np.ones((h, w), np.uint8) * 255
    return cropped_bgr, cropped_mask, (x, y, w, h)


# ─────────────────── 行内最佳 x ───────────────────

def _best_x_in_row(mat, target_row, tolerance=10):
    h, w = mat.shape
    y_lo = max(0, target_row - tolerance)
    y_hi = min(h, target_row + tolerance + 1)
    if y_lo >= y_hi:
        return 0, -1.0
    strip = mat[y_lo:y_hi, :]
    max_val = float(strip.max())
    idx = np.unravel_index(strip.argmax(), strip.shape)
    return int(idx[1]), max_val


def _topn_x_in_row(mat, target_row, tolerance=10, n=3, min_x=0, suppress=25):
    h, w = mat.shape
    y_lo = max(0, target_row - tolerance)
    y_hi = min(h, target_row + tolerance + 1)
    if y_lo >= y_hi:
        return []
    strip = mat[y_lo:y_hi, :].copy()
    if min_x > 0 and min_x < w:
        strip[:, :min_x] = -1.0

    results = []
    for _ in range(n):
        max_val = float(strip.max())
        if max_val <= 0:
            break
        idx = np.unravel_index(strip.argmax(), strip.shape)
        x = int(idx[1])
        results.append((x, max_val))
        lo = max(0, x - suppress)
        hi = min(w, x + suppress)
        strip[:, lo:hi] = -1.0
    return results


def _subpixel_x(mat, x, y):
    h, w = mat.shape
    y = min(max(0, y), h - 1)
    x = min(max(0, x), w - 1)
    if x <= 0 or x >= w - 1:
        return float(x)
    left = float(mat[y, x - 1])
    center = float(mat[y, x])
    right = float(mat[y, x + 1])
    denom = 2.0 * (2.0 * center - left - right)
    if abs(denom) < 1e-9:
        return float(x)
    offset = (left - right) / denom
    return x + max(-0.5, min(0.5, offset))


# ─────────────────── 核心识别 ───────────────────

def find_slider_offset(bg_img, piece_img, pp=None, top_k=5, debug=False):
    if isinstance(bg_img, str):
        bg_img = load_image_from_url(bg_img)
    if isinstance(piece_img, str):
        piece_img = load_image_from_url(piece_img)

    bg_bgr = _ensure_bgr(bg_img)
    piece_bgr, piece_mask, (crop_x, crop_y, pw, ph) = crop_by_alpha(piece_img)
    bg_gray = cv2.cvtColor(bg_bgr, cv2.COLOR_BGR2GRAY)
    piece_gray = cv2.cvtColor(piece_bgr, cv2.COLOR_BGR2GRAY)

    bg_h, bg_w = bg_gray.shape
    logger.info(f"      [识别] 背景: {bg_w}x{bg_h}, 滑块裁剪: {pw}x{ph}, 偏移: ({crop_x}, {crop_y})")

    fixed_y = int(pp[0]) if pp and len(pp) >= 1 else 0
    match_target_y = fixed_y + crop_y
    y_tol = max(ph // 2, 15)

    x_start = float(pp[1]) if pp and len(pp) >= 2 else 0
    min_match_x = max(int(x_start) + crop_x + pw // 2, 10)

    logger.info(f"      [识别] fixed_y={fixed_y}, match_y~{match_target_y}+-{y_tol}, min_match_x={min_match_x}")

    # 多阈值 Canny 边缘匹配
    bg_blur = cv2.GaussianBlur(bg_gray, (3, 3), 0)
    pc_blur = cv2.GaussianBlur(piece_gray, (3, 3), 0)

    canny_configs = [
        ("canny_lo",  30, 100),
        ("canny_mid", 50, 150),
        ("canny_hi",  80, 200),
    ]
    canny_mats = {}
    for name, lo, hi in canny_configs:
        bg_e = cv2.Canny(bg_blur, lo, hi)
        pc_e = cv2.Canny(pc_blur, lo, hi)
        if piece_mask is not None:
            pc_e = cv2.bitwise_and(pc_e, pc_e, mask=piece_mask)
        mat = cv2.matchTemplate(bg_e, pc_e, cv2.TM_CCOEFF_NORMED)
        canny_mats[name] = mat

    # 灰度匹配
    bg_gb = cv2.GaussianBlur(bg_gray, (5, 5), 0)
    pc_gb = cv2.GaussianBlur(piece_gray, (5, 5), 0)
    if piece_mask is not None:
        mat_gray = cv2.matchTemplate(bg_gb, pc_gb, cv2.TM_CCOEFF_NORMED, mask=piece_mask)
    else:
        mat_gray = cv2.matchTemplate(bg_gb, pc_gb, cv2.TM_CCOEFF_NORMED)

    # 颜色分通道
    ch_results = []
    for c in range(3):
        if piece_mask is not None:
            r = cv2.matchTemplate(bg_bgr[:, :, c], piece_bgr[:, :, c],
                                  cv2.TM_CCOEFF_NORMED, mask=piece_mask)
        else:
            r = cv2.matchTemplate(bg_bgr[:, :, c], piece_bgr[:, :, c],
                                  cv2.TM_CCOEFF_NORMED)
        ch_results.append(r)
    mat_color = np.mean(ch_results, axis=0)

    # Sobel 梯度
    bg_grad = cv2.magnitude(
        cv2.Sobel(bg_gray, cv2.CV_64F, 1, 0, ksize=3),
        cv2.Sobel(bg_gray, cv2.CV_64F, 0, 1, ksize=3)).astype(np.uint8)
    pc_grad = cv2.magnitude(
        cv2.Sobel(piece_gray, cv2.CV_64F, 1, 0, ksize=3),
        cv2.Sobel(piece_gray, cv2.CV_64F, 0, 1, ksize=3)).astype(np.uint8)
    if piece_mask is not None:
        pc_grad = cv2.bitwise_and(pc_grad, pc_grad, mask=piece_mask)
    mat_sobel = cv2.matchTemplate(bg_grad, pc_grad, cv2.TM_CCOEFF_NORMED)

    all_mats = {}
    all_mats.update(canny_mats)
    all_mats["gray"] = mat_gray
    all_mats["color"] = mat_color
    all_mats["sobel"] = mat_sobel

    # 每种方法取 Top-3 峰值
    method_peaks = {}
    for name, mat in all_mats.items():
        peaks = _topn_x_in_row(mat, match_target_y, tolerance=y_tol,
                               n=3, min_x=min_match_x, suppress=max(pw // 2, 20))
        method_peaks[name] = peaks
        for i, (px, ps) in enumerate(peaks):
            tag = "*" if i == 0 else " "
            logger.info(f"        {name:10s} #{i+1}{tag}: match_x={px}, score={ps:.4f}")

    # 交叉验证
    all_peaks = []
    for name, peaks in method_peaks.items():
        for rank, (px, ps) in enumerate(peaks):
            all_peaks.append((name, px, ps, rank))

    if not all_peaks:
        logger.info("      [识别] 无有效结果")
        return 0.0, fixed_y, [{"x": 0, "y": fixed_y, "w": pw, "h": ph, "score": 0}]

    confirm_radius = max(pw // 3, 10)
    best_match_x = None
    best_confirm = 0
    best_score = 0.0

    for anchor_name, anchor_x, anchor_score, anchor_rank in all_peaks:
        confirming = set()
        confirming.add(anchor_name)
        total_score = anchor_score

        for other_name, other_x, other_score, _ in all_peaks:
            if other_name == anchor_name:
                continue
            if abs(other_x - anchor_x) <= confirm_radius:
                confirming.add(other_name)
                total_score += other_score

        n_confirm = len(confirming)
        avg_score = total_score / n_confirm

        better = False
        if n_confirm > best_confirm:
            better = True
        elif n_confirm == best_confirm and avg_score > best_score:
            better = True

        if better:
            best_confirm = n_confirm
            best_score = avg_score
            sw, sx = 0.0, 0.0
            for mn, mx, ms, mr in all_peaks:
                if mn in confirming and abs(mx - anchor_x) <= confirm_radius:
                    w = ms * (1.0 if mr == 0 else 0.5)
                    sx += mx * w
                    sw += w
            best_match_x = sx / sw if sw > 0 else anchor_x

    # 亚像素精修
    best_canny_name = max(canny_mats.keys(),
                          key=lambda n: method_peaks[n][0][1] if method_peaks[n] else 0)
    mat_refine = canny_mats[best_canny_name]
    ix = int(round(best_match_x))
    iy = min(max(0, match_target_y), mat_refine.shape[0] - 1)
    ix = min(max(0, ix), mat_refine.shape[1] - 1)
    refined_match_x = _subpixel_x(mat_refine, ix, iy)

    final_x = refined_match_x - crop_x

    logger.info(f"      [识别] match_x={refined_match_x:.1f} - crop_x={crop_x} = slider_x={final_x:.1f}")
    logger.info(f"      [识别] 确认={best_confirm}/{len(all_mats)}方法")

    # 候选列表
    seen = set()
    candidates = []
    for name, peaks in method_peaks.items():
        for px, ps in peaks:
            adjusted = px - crop_x
            key = round(adjusted)
            if key not in seen:
                seen.add(key)
                candidates.append({
                    "x": round(adjusted, 1), "y": fixed_y,
                    "w": pw, "h": ph,
                    "score": round(ps, 5),
                    "method": name,
                })
    candidates.sort(key=lambda c: c["score"], reverse=True)
    candidates = candidates[:top_k]

    final_candidate = {
        "x": round(final_x, 1), "y": fixed_y,
        "w": pw, "h": ph,
        "score": round(best_score, 5),
        "confirm": best_confirm,
    }

    if debug:
        _save_debug(bg_bgr, fixed_y, crop_x, crop_y, refined_match_x, pw, ph, candidates)

    return round(final_x, 1), fixed_y, [final_candidate] + candidates


# ─────────────────── 调试 ───────────────────

def _save_debug(bg_bgr, fixed_y, crop_x, crop_y, match_x, pw, ph, candidates):
    _dir = os.path.dirname(os.path.abspath(__file__))
    vis = bg_bgr.copy()

    ref_y = fixed_y + crop_y
    cv2.line(vis, (0, ref_y), (vis.shape[1], ref_y), (255, 255, 0), 1)

    for i, c in enumerate(candidates):
        mx = int(round(c["x"])) + crop_x
        my = ref_y
        color = (0, 165, 255) if i > 0 else (0, 0, 255)
        thick = 1 if i > 0 else 2
        cv2.rectangle(vis, (mx, my), (mx + pw, my + ph), color, thick)
        label = f'{c.get("method", "")} {c["score"]:.3f}'
        ty = my - 6 if my > 20 else my + ph + 14
        cv2.putText(vis, label, (mx, ty), cv2.FONT_HERSHEY_SIMPLEX, 0.35, color, 1, cv2.LINE_AA)

    fx = int(round(match_x))
    cv2.rectangle(vis, (fx, ref_y), (fx + pw, ref_y + ph), (0, 255, 0), 2)
    cv2.putText(vis, f"x={match_x - crop_x:.1f}", (fx, ref_y - 8),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2, cv2.LINE_AA)

    _imwrite(os.path.join(_dir, "debug_result.png"), vis)
    logger.info(f"      [DEBUG] 已保存 debug_result.png")
