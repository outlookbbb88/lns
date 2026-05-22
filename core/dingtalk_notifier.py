#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""钉钉漏洞推送通知模块.

本模块提供钉钉机器人 Webhook 集成功能，用于在发现安全漏洞时
自动发送告警通知到钉钉群聊。

主要功能:
    - 钉钉 Webhook 加签认证 (HMAC-SHA256 + Base64 + URL编码)
    - 异步发送漏洞告警消息
    - Markdown 格式消息体构建
    - 完整的错误处理和日志记录

使用示例:
    >>> from core.dingtalk_notifier import DingTalkNotifier
    >>> notifier = DingTalkNotifier(
    ...     webhook_url="https://oapi.dingtalk.com/robot/send?access_token=xxx",
    ...     secret="SECxxx",
    ...     enabled=True
    ... )
    >>> vulnerability = {
    ...     "title": "SQL注入漏洞",
    ...     "vuln_type": "SQL注入",
    ...     "severity": "高危",
    ...     "description": "发现SQL注入漏洞",
    ...     "affected_url": "http://example.com/search",
    ...     "poc": "' OR '1'='1",
    ...     "evidence": "数据库错误信息泄露",
    ...     "reproduction_steps": ["访问搜索页面", "输入payload"],
    ...     "remediation": "使用参数化查询",
    ...     "discovered_at": "2024-01-01 12:00:00"
    ... }
    >>> await notifier.send_vulnerability_alert(vulnerability)
    True
"""

import hmac
import hashlib
import base64
import urllib.parse
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 钉钉加签算法
# ---------------------------------------------------------------------------


def _generate_sign(secret: str, timestamp: str) -> str:
    """生成钉钉 webhook 签名.

    使用钉钉官方推荐的加签算法：HMAC-SHA256 对 ``timestamp\nsecret`` 进行签名，
    再对签名结果进行 Base64 编码，最后进行 URL 编码。

    Args:
        secret: 钉钉机器人加签密钥（以 SEC 开头的字符串）。
        timestamp: 毫秒级时间戳字符串。

    Returns:
        经过 URL 编码后的签名字符串，可直接拼接到 Webhook URL 中使用。

    参考文档:
        https://open.dingtalk.com/document/robots/custom-robot-access
    """
    string_to_sign = f"{timestamp}\n{secret}"
    sign = hmac.new(
        secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).digest()
    sign = base64.b64encode(sign).decode("utf-8")
    return urllib.parse.quote_plus(sign)


# ---------------------------------------------------------------------------
# DingTalkNotifier 类
# ---------------------------------------------------------------------------


class DingTalkNotifier:
    """钉钉漏洞推送通知器.

    通过钉钉群机器人 Webhook 接口，将漏洞发现信息以 Markdown 格式
    推送到指定钉钉群聊。支持加签认证和 @所有人 功能。

    Attributes:
        webhook_url: 钉钉机器人 Webhook 地址。
        secret: 钉钉机器人加签密钥。
        enabled: 是否启用推送功能。设为 False 时所有发送操作将被静默跳过。

    Example:
        >>> notifier = DingTalkNotifier(
        ...     webhook_url="https://oapi.dingtalk.com/robot/send?access_token=xxx",
        ...     secret="SECxxx"
        ... )
        >>> success = await notifier.send_vulnerability_alert(vuln_dict)
    """

    def __init__(
        self,
        webhook_url: str,
        secret: str,
        enabled: bool = True,
    ) -> None:
        """初始化钉钉推送通知器.

        Args:
            webhook_url: 钉钉机器人 Webhook 完整地址（含 access_token）。
            secret: 钉钉机器人加签密钥（SEC 开头）。
            enabled: 是否启用推送。默认为 True。
        """
        self.webhook_url: str = webhook_url
        self.secret: str = secret
        self.enabled: bool = enabled

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    def _generate_sign(self, timestamp: str) -> str:
        """生成加签.

        对当前实例的 secret 和给定时间戳进行加签计算。

        Args:
            timestamp: 毫秒级时间戳字符串。

        Returns:
            URL 编码后的签名字符串。
        """
        return _generate_sign(self.secret, timestamp)

    def _build_markdown_message(self, vuln: dict) -> dict:
        """构建钉钉 markdown 消息体.

        根据漏洞信息字典构建符合钉钉机器人接口规范的 markdown 消息结构。
        消息格式包含醒目的标题、漏洞概述、详细描述、PoC 代码、验证证据、
        复现步骤和修复建议等部分。

        Args:
            vuln: 漏洞信息字典，预期包含以下字段：
                - title (str): 漏洞标题
                - vuln_type (str): 漏洞类型（如 SQL注入、XSS、RCE 等）
                - severity (str): 严重程度（严重/高危/中危/低危）
                - description (str): 漏洞详细描述
                - affected_url (str): 受影响的 URL
                - poc (str): 完整 PoC（利用代码/步骤）
                - evidence (str): 验证证据（截图/返回数据）
                - reproduction_steps (list[str]): 复现步骤列表
                - remediation (str): 修复建议
                - discovered_at (str): 发现时间

        Returns:
            符合钉钉机器人接口规范的 dict 消息体，可直接作为 JSON payload
            发送到钉钉 Webhook 接口。

        Note:
            对于缺少的字段，方法会使用 ``"N/A"`` 或 ``["暂无步骤"]`` 作为
            默认值填充，确保消息格式完整。
        """
        title: str = vuln.get("title", "未命名漏洞")
        vuln_type: str = vuln.get("vuln_type", "未知类型")
        severity: str = vuln.get("severity", "未知")
        description: str = vuln.get("description", "暂无描述")
        affected_url: str = vuln.get("affected_url", "N/A")
        poc: str = vuln.get("poc", "暂无 PoC")
        evidence: str = vuln.get("evidence", "暂无证据")
        reproduction_steps: list = vuln.get("reproduction_steps", ["暂无步骤"])
        remediation: str = vuln.get("remediation", "暂无修复建议")
        discovered_at: str = vuln.get("discovered_at", "未知时间")

        # 根据严重程度选择对应的 emoji
        severity_emoji_map = {
            "严重": "🔴",
            "高危": "🟠",
            "中危": "🟡",
            "低危": "🟢",
        }
        sev_emoji = severity_emoji_map.get(severity, "⚪")

        # 构建复现步骤文本
        steps_text = "\n".join(
            f"{idx}. {step}" for idx, step in enumerate(reproduction_steps, 1)
        )

        markdown_text = (
            f"## 🚨 漏洞发现通知 —— {title}（{severity}）\n\n"
            f"---\n\n"
            f"**🎯 漏洞概述**\n\n"
            f"- **漏洞类型**：{vuln_type}\n"
            f"- **严重程度**：{sev_emoji} {severity}\n"
            f"- **影响 URL**：{affected_url}\n"
            f"- **发现时间**：{discovered_at}\n\n"
            f"---\n\n"
            f"**📝 漏洞描述**\n\n"
            f"{description}\n\n"
            f"---\n\n"
            f"**💥 完整 PoC**\n\n"
            f"```\n{poc}\n```\n\n"
            f"---\n\n"
            f"**🔍 验证证据**\n\n"
            f"> {evidence}\n\n"
            f"---\n\n"
            f"**📋 复现步骤**\n\n"
            f"{steps_text}\n\n"
            f"---\n\n"
            f"**💡 修复建议**\n\n"
            f"{remediation}\n\n"
            f"---\n\n"
            f"**⚠️ 测试已自动停止**\n\n"
            f"已发现有效漏洞，测试任务已自动终止。"
        )

        message = {
            "msgtype": "markdown",
            "markdown": {
                "title": f"🚨 漏洞发现通知 —— {title}",
                "text": markdown_text,
            },
            "at": {
                "isAtAll": True,
            },
        }

        return message

    # ------------------------------------------------------------------
    # 公共接口
    # ------------------------------------------------------------------

    async def send_vulnerability_alert(self, vulnerability: dict) -> bool:
        """发送漏洞发现通知到钉钉.

        异步将漏洞信息以 Markdown 格式推送到钉钉群聊。
        如果 ``enabled`` 为 False，则直接返回 False 不执行发送。
        发送失败时会记录错误日志并返回 False，不会抛出异常。

        Args:
            vulnerability: 漏洞信息字典，预期包含以下字段：
                - title (str): 漏洞标题
                - vuln_type (str): 漏洞类型（如 SQL注入、XSS、RCE 等）
                - severity (str): 严重程度（严重/高危/中危/低危）
                - description (str): 漏洞详细描述
                - affected_url (str): 受影响的 URL
                - poc (str): 完整 PoC（利用代码/步骤）
                - evidence (str): 验证证据（截图/返回数据）
                - reproduction_steps (list[str]): 复现步骤列表
                - remediation (str): 修复建议
                - discovered_at (str): 发现时间

        Returns:
            发送是否成功。True 表示钉钉接口返回成功，False 表示发送失败
            或通知器处于禁用状态。
        """
        if not self.enabled:
            logger.debug("DingTalk notifier is disabled, skipping alert.")
            return False

        try:
            # 构建消息体
            message_payload = self._build_markdown_message(vulnerability)

            # 获取毫秒级时间戳
            import time

            timestamp = str(int(round(time.time() * 1000)))

            # 生成签名
            sign = self._generate_sign(timestamp)

            # 构造带签名的完整 URL
            separator = "&" if "?" in self.webhook_url else "?"
            signed_url = (
                f"{self.webhook_url}{separator}"
                f"timestamp={timestamp}&sign={sign}"
            )

            # 发送异步 HTTP POST 请求
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    signed_url,
                    json=message_payload,
                    headers={"Content-Type": "application/json; charset=utf-8"},
                )
                response.raise_for_status()
                result = response.json()

            # 检查钉钉接口返回码
            errcode = result.get("errcode", -1)
            if errcode == 0:
                logger.info(
                    "DingTalk vulnerability alert sent successfully: %s",
                    vulnerability.get("title", "unknown"),
                )
                return True
            else:
                errmsg = result.get("errmsg", "unknown error")
                logger.error(
                    "DingTalk API returned error: errcode=%s, errmsg=%s",
                    errcode,
                    errmsg,
                )
                return False

        except httpx.HTTPStatusError as exc:
            logger.error(
                "DingTalk HTTP error: status_code=%s, response=%s",
                exc.response.status_code,
                exc.response.text,
            )
            return False
        except httpx.RequestError as exc:
            logger.error("DingTalk request error: %s", exc)
            return False
        except Exception as exc:
            logger.exception("Unexpected error sending DingTalk alert: %s", exc)
            return False

    async def send_text_alert(self, content: str) -> bool:
        """发送纯文本告警到钉钉.

        用于发送简单的文本通知（如系统状态、测试开始/结束通知等），
        不构建复杂的 Markdown 消息体。

        Args:
            content: 要发送的纯文本内容。

        Returns:
            发送是否成功。
        """
        if not self.enabled:
            logger.debug("DingTalk notifier is disabled, skipping text alert.")
            return False

        try:
            import time

            timestamp = str(int(round(time.time() * 1000)))
            sign = self._generate_sign(timestamp)

            separator = "&" if "?" in self.webhook_url else "?"
            signed_url = (
                f"{self.webhook_url}{separator}"
                f"timestamp={timestamp}&sign={sign}"
            )

            message_payload = {
                "msgtype": "text",
                "text": {"content": content},
                "at": {"isAtAll": True},
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    signed_url,
                    json=message_payload,
                    headers={"Content-Type": "application/json; charset=utf-8"},
                )
                response.raise_for_status()
                result = response.json()

            errcode = result.get("errcode", -1)
            if errcode == 0:
                logger.info("DingTalk text alert sent successfully.")
                return True
            else:
                errmsg = result.get("errmsg", "unknown error")
                logger.error(
                    "DingTalk API returned error: errcode=%s, errmsg=%s",
                    errcode,
                    errmsg,
                )
                return False

        except httpx.HTTPStatusError as exc:
            logger.error(
                "DingTalk HTTP error: status_code=%s, response=%s",
                exc.response.status_code,
                exc.response.text,
            )
            return False
        except httpx.RequestError as exc:
            logger.error("DingTalk request error: %s", exc)
            return False
        except Exception as exc:
            logger.exception("Unexpected error sending DingTalk text alert: %s", exc)
            return False
