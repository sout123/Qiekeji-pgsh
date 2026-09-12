#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""胖乖生活手机号验证码登录示例。

脚本依据 HAR 中观察到的请求流程编写：
1. 检查是否需要图形验证码；
2. 发送短信验证码；
3. 使用手机号和短信验证码调用 user/reg 完成登录。

注意：不要把真实手机号、短信验证码或登录 Token 写入源代码、日志或提交记录。
"""

from __future__ import annotations

import argparse
import hashlib
import getpass
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import requests


基础地址 = "https://userapi.qiekj.com"
默认超时秒数 = 15
默认设备号 = ""
应用版本 = "1.139.0"
应用密钥 = "nFU9pbG8YQoAe1kFh+E7eyrdlSLglwEJeA0wwHB1j5o="
登录状态文件 = Path(__file__).with_name("登录状态.json")


def build_signature(timestamp: str, token: str, path: str, version: str = 应用版本) -> str:
    """按照客户端拦截器的固定字段顺序生成小写 SHA-256 签名。"""
    raw = (
        f"appSecret={应用密钥}"
        f"&channel=android_app"
        f"&timestamp={timestamp}"
        f"&token={token}"
        f"&version={version}"
        f"&{path}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_order_risk_signature(
    category_code: str,
    imei: str,
    latitude: str,
    longitude: str,
    timestamp: str,
    token: str,
    path: str,
) -> str:
    """生成解锁接口使用的定位风控签名。"""
    raw = (
        f"appSecret={应用密钥}"
        f"&categoryCode={category_code}"
        f"&channel=android_app"
        f"&imei={imei}"
        f"&lat={latitude}"
        f"&lng={longitude}"
        f"&timestamp={timestamp}"
        f"&token={token}"
        f"&version={应用版本}"
        f"&{path}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class 登录协议错误(RuntimeError):
    """服务端返回业务错误或响应格式异常时抛出。"""


@dataclass
class 登录结果:
    令牌: str
    新用户: bool
    强制绑定: bool


def 读取登录态(路径: Path = 登录状态文件) -> dict[str, Any] | None:
    """读取本地登录态；文件不存在或内容损坏时返回空。"""
    if not 路径.exists():
        return None
    try:
        数据 = json.loads(路径.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(数据, dict) or not 数据.get("token") or not 数据.get("deviceId"):
        return None
    return 数据


def 保存登录态(
    令牌: str,
    设备号: str,
    手机号: str,
    session: requests.Session,
    路径: Path = 登录状态文件,
) -> None:
    """保存复用登录所需的 Token、设备号和会话 Cookie。"""
    数据 = {
        "token": 令牌,
        "deviceId": 设备号,
        "phone": 手机号,
        "version": 应用版本,
        "savedAt": int(time.time()),
        "cookies": session.cookies.get_dict(),
    }
    路径.parent.mkdir(parents=True, exist_ok=True)
    临时文件 = 路径.with_suffix(".tmp")
    临时文件.write_text(json.dumps(数据, ensure_ascii=False, indent=2), encoding="utf-8")
    临时文件.replace(路径)
    try:
        路径.chmod(0o600)
    except OSError:
        # Windows 下 ACL 可能不支持 POSIX 权限，文件仍会保存。
        pass


def 清除登录态(路径: Path = 登录状态文件) -> None:
    """删除本地登录态文件。"""
    try:
        路径.unlink()
    except FileNotFoundError:
        pass


def _请求(
    session: requests.Session,
    路径: str,
    数据: dict[str, str],
    超时: int,
    设备号: str,
    额外请求头: dict[str, str] | None = None,
) -> dict[str, Any]:
    """发送表单请求并统一检查 HTTP 与业务层状态。"""
    # 登录接口会检查移动端公共请求头；HAR 中的 timestamp 每次请求都会变化。
    timestamp = (额外请求头 or {}).get("timestamp", str(int(time.time() * 1000)))
    token = str(数据.get("token", ""))
    sign = build_signature(timestamp, token, 路径)
    请求头 = {
        "Authorization": token,
        "Version": 应用版本,
        "channel": "android_app",
        "phoneBrand": "OnePlus",
        "deviceId": 设备号,
        "timestamp": timestamp,
        "sign": sign,
        "User-Agent": "QEUser/1.139.0 (com.qiekj.user; build:234; Android 16; userChannel:android_app; version:1.139.0) OkHttp/4.12.0",
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        # 以下三个头与 HAR 中的 OkHttp 请求保持一致，避免被网关按请求形态拦截。
        "Host": "userapi.qiekj.com",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }
    if 额外请求头:
        请求头.update(额外请求头)
    response = session.post(
        f"{基础地址}{路径}",
        data=数据,
        headers=请求头,
        timeout=超时,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        if response.status_code in (401, 403, 405):
            raise 登录协议错误(
                f"接口 {路径} 拒绝请求（HTTP {response.status_code}）。"
                "请确认 deviceId、timestamp 和 sign 均按客户端规则生成。"
            ) from exc
        raise
    try:
        内容 = response.json()
    except ValueError as exc:
        raise 登录协议错误(f"接口 {路径} 返回的不是 JSON") from exc

    if 内容.get("code") != 0:
        raise 登录协议错误(
            f"接口 {路径} 失败：code={内容.get('code')}，msg={内容.get('msg', '未知错误')}"
        )
    return 内容


def 检查图形验证码(session: requests.Session, 手机号: str, 超时: int, 设备号: str) -> bool:
    """返回服务端是否要求图形验证码。"""
    内容 = _请求(session, "/common/isNeedCaptcha", {"phone": 手机号}, 超时, 设备号)
    return bool(内容.get("data"))


def 发送短信验证码(session: requests.Session, 手机号: str, 超时: int, 设备号: str) -> None:
    """请求发送登录短信；HAR 中该接口使用 template=reg。"""
    _请求(
        session,
        "/common/sms/sendCode",
        {"phone": 手机号, "template": "reg"},
        超时,
        设备号,
    )


def 手机号登录(
    session: requests.Session,
    手机号: str,
    短信验证码: str,
    超时: int,
    设备号: str,
) -> 登录结果:
    """提交手机号和短信验证码，返回会话 Token。"""
    内容 = _请求(
        session,
        "/user/reg",
        {
            "channel": "android_app",
            "phone": 手机号,
            "verify": 短信验证码,
        },
        超时,
        设备号,
    )
    数据 = 内容.get("data") or {}
    令牌 = 数据.get("token")
    if not isinstance(令牌, str) or not 令牌:
        raise 登录协议错误("登录响应中没有找到 token")

    return 登录结果(
        令牌=令牌,
        新用户=bool(数据.get("newRegister")),
        强制绑定=bool(数据.get("forcedBind")),
    )


def 查询余额(
    session: requests.Session,
    令牌: str,
    超时: int,
    设备号: str,
) -> dict[str, Any]:
    """查询账户余额、积分和积分可抵扣金额。"""
    内容 = _请求(session, "/user/balance", {"token": 令牌}, 超时, 设备号)
    数据 = 内容.get("data") or {}
    token_coin = 数据.get("tokenCoin")
    integral = 数据.get("integral")
    integral_amount = 数据.get("integralAmount")
    if not isinstance(token_coin, (int, float)):
        raise 登录协议错误("余额响应中缺少有效的 tokenCoin")
    if not isinstance(integral, (int, float)):
        raise 登录协议错误("余额响应中缺少有效的 integral")
    if integral_amount is None:
        raise 登录协议错误("余额响应中缺少 integralAmount")

    结果 = {
        "tokenCoin": token_coin,
        "余额": token_coin / 100,
        "integral": integral,
        "integralAmount": str(integral_amount),
    }
    print(json.dumps(结果, ensure_ascii=False, indent=2))
    return 结果


def parse_scan_url(scan_url: str) -> str:
    """从扫码结果 URL 中提取 SN 参数。"""
    parsed = urlparse(scan_url.strip())
    sn = parse_qs(parsed.query).get("SN", [""])[0].strip()
    if not sn:
        raise 登录协议错误("扫码链接中没有找到 SN 参数")
    return sn


def scan_goods(session: requests.Session, token: str, device_id: str, timeout: int, scan_url: str) -> dict[str, Any]:
    """通过二维码 SN 获取商品基本信息。"""
    sn = parse_scan_url(scan_url)
    content = _请求(session, "/goods/scan/v2", {"SN": sn, "token": token}, timeout, device_id)
    data = content.get("data") or {}
    goods_id = data.get("id")
    if not goods_id:
        raise 登录协议错误("扫码接口没有返回 goodsId")
    data["goodsId"] = str(goods_id)
    print(json.dumps({"扫码SN": sn, "商品信息": data}, ensure_ascii=False, indent=2))
    return data


def get_goods_details(session: requests.Session, token: str, device_id: str, timeout: int, goods_id: str) -> dict[str, Any]:
    """获取饮水机详情，包括 orgId、IMEI、shopId 等解锁参数。"""
    content = _请求(session, "/goods/normal/details", {"goodsId": goods_id, "token": token}, timeout, device_id)
    data = content.get("data") or {}
    required = ("goodsId", "categoryCode", "orgId", "imei", "shopId")
    missing = [name for name in required if data.get(name) in (None, "")]
    if missing:
        raise 登录协议错误(f"商品详情缺少解锁字段：{', '.join(missing)}")
    print(json.dumps({
        "商品ID": data.get("goodsId"),
        "名称": data.get("name"),
        "分类": data.get("categoryCode"),
        "机构ID": data.get("orgId"),
        "设备IMEI": data.get("imei"),
        "店铺ID": data.get("shopId"),
        "机器ID": data.get("machineId"),
        "支付模式": data.get("payment"),
    }, ensure_ascii=False, indent=2))
    return data


def get_goods_skus(session: requests.Session, token: str, device_id: str, timeout: int, goods_id: str) -> list[dict[str, Any]]:
    """获取商品 SKU 列表，解锁使用 skuId 而不是 goodsId。"""
    content = _请求(session, "/goods/normal/skus", {"goodsId": goods_id, "token": token}, timeout, device_id)
    skus = content.get("data") or []
    if not isinstance(skus, list) or not skus:
        raise 登录协议错误("商品没有可用 SKU")
    return skus


def build_promotions(use_integral: bool) -> str:
    """构造积分抵扣开关；8 启用，-8 不启用。"""
    promotions = [
        {"assetId": "0", "oldPromotionId": "", "orgId": "0", "promotionId": "0", "promotionType": "-6"},
        {"assetId": "0", "oldPromotionId": "", "orgId": "0", "promotionId": "0", "promotionType": "-7"},
        {"assetId": "0", "oldPromotionId": "0", "orgId": "0", "promotionId": "0", "promotionType": "8" if use_integral else "-8"},
    ]
    return json.dumps(promotions, ensure_ascii=False, separators=(",", ":"))


def check_integral_available(session: requests.Session, token: str, device_id: str, timeout: int) -> None:
    """读取积分使用规则，并在服务端风控拒绝时停止流程。"""
    rule_content = _请求(session, "/userIntegral/limitRule", {"token": token}, timeout, device_id)
    rule = rule_content.get("data") or {}
    print(json.dumps({"积分规则": rule}, ensure_ascii=False, indent=2))
    risk_content = _请求(session, "/userIntegral/checkUserIsRisk", {"token": token}, timeout, device_id)
    if risk_content.get("data") is True:
        raise 登录协议错误("服务端判定当前账号不能使用积分抵扣")


def prepare_unlock(session: requests.Session, token: str, device_id: str, timeout: int, details: dict[str, Any]) -> None:
    """执行解锁前的支付渠道和位置风控检查。"""
    _请求(session, "/payChannelRoute/addUserAfterPayChannel", {"method": "15", "token": token}, timeout, device_id)
    _请求(
        session,
        "/orderRisk/isCheckLocation",
        {
            "categoryCode": str(details.get("categoryCode", "")),
            "imei": str(details.get("imei", "")),
            "orgId": str(details.get("orgId", "")),
            "token": token,
        },
        timeout,
        device_id,
    )


def unlock_water(
    session: requests.Session,
    token: str,
    device_id: str,
    timeout: int,
    sku_id: str,
    details: dict[str, Any],
    use_integral: bool,
    latitude: str,
    longitude: str,
) -> dict[str, Any]:
    """提交饮水机解锁请求；该操作会产生真实设备和订单状态变化。"""
    category_code = str(details.get("categoryCode", ""))
    imei = str(details.get("imei", ""))
    timestamp = str(int(time.time() * 1000))
    extra_headers = {
        "imei": imei,
        "categoryCode": category_code,
        "timestamp": timestamp,
    }
    if latitude and longitude:
        extra_headers["lat"] = latitude
        extra_headers["lng"] = longitude
        extra_headers["orderRiskSign"] = build_order_risk_signature(
            category_code, imei, latitude, longitude, timestamp, token, "/goods/water/unlock"
        )
        extra_headers["orderRiskTimestamp"] = timestamp

    # _请求会重新生成普通 sign；这里让两种时间戳一致，避免风控签名失配。
    content = _请求(
        session,
        "/goods/water/unlock",
        {"skuId": sku_id, "promotions": build_promotions(use_integral), "token": token},
        timeout,
        device_id,
        extra_headers,
    )
    data = content.get("data") or {}
    if not data.get("orderNo"):
        raise 登录协议错误("解锁响应没有返回 orderNo")
    return data


def poll_water_status(
    session: requests.Session,
    token: str,
    device_id: str,
    timeout: int,
    sku_id: str,
    max_attempts: int = 60,
) -> dict[str, Any]:
    """轮询设备状态，区分工作中、未使用和已使用。"""
    last_data: dict[str, Any] = {}
    for attempt in range(max_attempts):
        content = _请求(session, "/goods/water/sync", {"skuId": sku_id, "token": token}, timeout, device_id)
        data = content.get("data") or {}
        last_data = data
        work_status = data.get("workStatus")
        amount = data.get("amount")
        if work_status != 2 and amount is not None:
            if isinstance(amount, (int, float)) and amount > 0:
                print(f"设备状态：已使用，设备使用量={amount}")
            else:
                print("设备状态：已解锁，但未产生使用量。")
            return data
        print(f"设备状态：工作中（第 {attempt + 1} 次轮询）")
        time.sleep(1.5)
    raise 登录协议错误(f"设备状态轮询超时，最后结果：{last_data}")


def get_order_detail(
    session: requests.Session,
    token: str,
    device_id: str,
    timeout: int,
    order_id: str,
) -> dict[str, Any]:
    """查询最终订单详情并输出金额、抵扣和使用值。"""
    content = _请求(session, "/order/detail", {"orderId": order_id, "token": token}, timeout, device_id)
    data = content.get("data") or {}
    trade_items = data.get("tradeOrderItem") or []
    item = trade_items[0] if trade_items else {}
    sku_info = item.get("skuInfo") or {}
    result = {
        "订单号": data.get("orderNo"),
        "订单状态": data.get("orderStatus"),
        "机器名称": data.get("machineName"),
        "功能": data.get("machineFunctionName"),
        "标价": data.get("markPrice"),
        "实付": data.get("payPrice"),
        "余额抵扣": data.get("tokenCoinDiscount"),
        "订单使用值": sku_info.get("waterUseValue"),
        "优惠记录": data.get("promotionList"),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return data


def create_and_query_order(
    session: requests.Session,
    token: str,
    device_id: str,
    timeout: int,
    order_no: str,
) -> dict[str, Any]:
    """实际使用后创建并同步订单，再读取账单。"""
    _请求(session, "/order/afterPay/creating", {"orderNo": order_no, "token": token}, timeout, device_id)
    for _ in range(10):
        content = _请求(
            session,
            "/order/sync",
            {"orderNo": order_no, "payType": "0", "token": token},
            timeout,
            device_id,
        )
        data = content.get("data") or {}
        if data.get("code") == 0:
            return get_order_detail(session, token, device_id, timeout, order_no)
        time.sleep(1)
    print("订单仍在同步，暂未读取到最终账单。")
    return {}


def run_scan_flow(
    session: requests.Session,
    token: str,
    device_id: str,
    timeout: int,
    scan_url: str,
    use_integral: bool,
    latitude: str,
    longitude: str,
) -> None:
    """执行扫码识别、选择抵扣、解锁、状态判断和订单查询。"""
    scan_data = scan_goods(session, token, device_id, timeout, scan_url)
    goods_id = str(scan_data["goodsId"])
    details = get_goods_details(session, token, device_id, timeout, goods_id)
    skus = get_goods_skus(session, token, device_id, timeout, goods_id)
    print("可用商品 SKU：")
    for index, sku in enumerate(skus):
        print(f"[{index}] skuId={sku.get('skuId')} 名称={sku.get('name')} 价格={sku.get('price')}")
    choice = input("请选择 SKU 编号（默认 0）：").strip() or "0"
    try:
        sku = skus[int(choice)]
    except (ValueError, IndexError):
        raise 登录协议错误("SKU 编号无效")
    sku_id = str(sku.get("skuId"))
    print(f"积分抵扣：{'启用' if use_integral else '不启用'}（promotionType={'8' if use_integral else '-8'}）")
    if use_integral:
        check_integral_available(session, token, device_id, timeout)
    if input("确认执行真实解锁？请输入 YES：").strip() != "YES":
        print("已取消解锁。")
        return
    prepare_unlock(session, token, device_id, timeout, details)
    unlock_data = unlock_water(
        session, token, device_id, timeout, sku_id, details, use_integral, latitude, longitude
    )
    order_no = str(unlock_data["orderNo"])
    print(f"解锁成功：msgId={unlock_data.get('msgId')} orderNo={order_no}")
    status = poll_water_status(session, token, device_id, timeout, sku_id)
    amount = status.get("amount")
    if not isinstance(amount, (int, float)) or amount <= 0:
        print("本次结果：已解锁但未使用，不创建消费订单。"); return
    create_and_query_order(session, token, device_id, timeout, order_no)


def _脱敏令牌(令牌: str) -> str:
    """默认只显示首尾少量字符，避免令牌泄露到终端记录。"""
    if len(令牌) <= 8:
        return "[已隐藏]"
    return f"{令牌[:4]}...{令牌[-4:]}"


def 主程序() -> int:
    解析器 = argparse.ArgumentParser(description="胖乖生活手机号验证码登录")
    解析器.add_argument("--手机号", help="手机号；不提供时交互输入")
    解析器.add_argument("--超时", type=int, default=默认超时秒数, help="单次请求超时秒数")
    解析器.add_argument("--设备ID", default=默认设备号, help="客户端设备 ID；可从本人抓包中取得")
    解析器.add_argument("--显示令牌", action="store_true", help="显示完整登录 Token（谨慎使用）")
    解析器.add_argument("--重新登录", action="store_true", help="忽略本地登录态，重新发送短信登录")
    解析器.add_argument("--清除登录态", action="store_true", help="删除本地登录态后退出")
    解析器.add_argument("--状态文件", type=Path, default=登录状态文件, help="本地登录态 JSON 文件路径")
    解析器.add_argument("--扫描链接", help="二维码识别结果，例如 https://h5.qiekj.com/skip?SN=...")
    抵扣组 = 解析器.add_mutually_exclusive_group()
    抵扣组.add_argument("--使用积分", action="store_true", help="解锁时使用积分抵扣")
    抵扣组.add_argument("--不使用积分", action="store_true", help="解锁时不使用积分抵扣")
    解析器.add_argument("--纬度", default="", help="解锁风控纬度，可选")
    解析器.add_argument("--经度", default="", help="解锁风控经度，可选")
    参数 = 解析器.parse_args()

    if 参数.清除登录态:
        清除登录态(参数.状态文件)
        print(f"已清除登录态：{参数.状态文件}")
        return 0

    session = requests.Session()
    session.headers.update({
        # HTTP 请求头不能直接使用中文，使用 ASCII 兼容的 Android UA。
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 16; Android SDK built for x86_64)",
    })

    try:
        本地登录态 = None if 参数.重新登录 else 读取登录态(参数.状态文件)
        if 本地登录态:
            设备号 = 参数.设备ID or str(本地登录态["deviceId"])
            session.cookies.update(本地登录态.get("cookies", {}))
            print("已读取本地登录态，跳过短信登录。")
            print("账户余额与积分：")
            查询余额(session, str(本地登录态["token"]), 参数.超时, 设备号)
            扫描链接 = 参数.扫描链接 or input("扫码结果URL（回车仅查看余额）：").strip()
            if 扫描链接:
                if not 参数.使用积分 and not 参数.不使用积分:
                    使用积分 = input("本次使用积分抵扣？请输入 Y/N：").strip().upper() == "Y"
                else:
                    使用积分 = 参数.使用积分
                run_scan_flow(
                    session,
                    str(本地登录态["token"]),
                    设备号,
                    参数.超时,
                    扫描链接,
                    使用积分,
                    参数.纬度,
                    参数.经度,
                )
            return 0

        手机号 = 参数.手机号 or input("手机号：").strip()
        if not 手机号.isdigit() or len(手机号) < 6:
            print("手机号格式不正确。", file=sys.stderr)
            return 2
        设备号 = 参数.设备ID or input("设备ID（可从本人抓包请求头取得）：").strip()
        if not 设备号:
            print("缺少设备ID；该接口会校验移动端设备请求头。", file=sys.stderr)
            return 2

        需要图形验证码 = 检查图形验证码(session, 手机号, 参数.超时, 设备号)

        if 需要图形验证码:
            print("服务端要求图形验证码；当前脚本未实现图形验证码识别，请先完成验证后再继续。")
            return 3

        发送短信验证码(session, 手机号, 参数.超时, 设备号)
        print("短信验证码已发送。")
        短信验证码 = getpass.getpass("短信验证码：").strip()
        if not 短信验证码:
            print("短信验证码不能为空。", file=sys.stderr)
            return 2

        结果 = 手机号登录(session, 手机号, 短信验证码, 参数.超时, 设备号)
        保存登录态(结果.令牌, 设备号, 手机号, session, 参数.状态文件)
        print(f"登录态已保存：{参数.状态文件}")
        输出令牌 = 结果.令牌 if 参数.显示令牌 else _脱敏令牌(结果.令牌)
        print(json.dumps({
            "登录成功": True,
            "token": 输出令牌,
            "newRegister": 结果.新用户,
            "forcedBind": 结果.强制绑定,
        }, ensure_ascii=False, indent=2))
        print("账户余额与积分：")
        查询余额(session, 结果.令牌, 参数.超时, 设备号)
        扫描链接 = 参数.扫描链接 or input("扫码结果URL（回车仅查看余额）：").strip()
        if 扫描链接:
            if not 参数.使用积分 and not 参数.不使用积分:
                使用积分 = input("本次使用积分抵扣？请输入 Y/N：").strip().upper() == "Y"
            else:
                使用积分 = 参数.使用积分
            run_scan_flow(
                session,
                结果.令牌,
                设备号,
                参数.超时,
                扫描链接,
                使用积分,
                参数.纬度,
                参数.经度,
            )
        return 0
    except requests.RequestException as exc:
        print(f"网络请求失败：{exc}", file=sys.stderr)
        return 1
    except 登录协议错误 as exc:
        print(f"登录失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(主程序())
