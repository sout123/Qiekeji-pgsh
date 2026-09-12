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
from typing import Any

import requests


基础地址 = "https://userapi.qiekj.com"
默认超时秒数 = 15
默认设备号 = ""
应用版本 = "1.139.0"
应用密钥 = "nFU9pbG8YQoAe1kFh+E7eyrdlSLglwEJeA0wwHB1j5o="


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


class 登录协议错误(RuntimeError):
    """服务端返回业务错误或响应格式异常时抛出。"""


@dataclass
class 登录结果:
    令牌: str
    新用户: bool
    强制绑定: bool


def _请求(
    session: requests.Session,
    路径: str,
    数据: dict[str, str],
    超时: int,
    设备号: str,
) -> dict[str, Any]:
    """发送表单请求并统一检查 HTTP 与业务层状态。"""
    # 登录接口会检查移动端公共请求头；HAR 中的 timestamp 每次请求都会变化。
    timestamp = str(int(time.time() * 1000))
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
    参数 = 解析器.parse_args()

    手机号 = 参数.手机号 or input("手机号：").strip()
    if not 手机号.isdigit() or len(手机号) < 6:
        print("手机号格式不正确。", file=sys.stderr)
        return 2
    设备号 = 参数.设备ID or input("设备ID（可从本人抓包请求头取得）：").strip()
    if not 设备号:
        print("缺少设备ID；该接口会校验移动端设备请求头。", file=sys.stderr)
        return 2

    session = requests.Session()
    session.headers.update({
        # HTTP 请求头不能直接使用中文，使用 ASCII 兼容的 Android UA。
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 16; Android SDK built for x86_64)",
        "Accept": "application/json",
    })

    try:
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
        输出令牌 = 结果.令牌 if 参数.显示令牌 else _脱敏令牌(结果.令牌)
        print(json.dumps({
            "登录成功": True,
            "token": 输出令牌,
            "newRegister": 结果.新用户,
            "forcedBind": 结果.强制绑定,
        }, ensure_ascii=False, indent=2))
        return 0
    except requests.RequestException as exc:
        print(f"网络请求失败：{exc}", file=sys.stderr)
        return 1
    except 登录协议错误 as exc:
        print(f"登录失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(主程序())
