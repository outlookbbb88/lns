"""
安全围栏核心模块 (Security Guardrails Core Module)

实现渗透测试的行为红线和无效漏洞类型过滤。
对工具调用进行实时安全检查，防止危险操作破坏生产环境或泄露敏感数据。
"""

import re
import time
import logging
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import dataclass, field

from core.data_contracts import GuardrailViolation, InvalidVulnType
from conf.config import (
    GUARDRAILS_ENABLED,
    GUARDRAILS_MAX_SENSITIVE_RECORDS,
    GUARDRAILS_BLOCK_DANGEROUS_SQL,
    GUARDRAILS_BLOCK_DOS,
    GUARDRAILS_BLOCK_FILE_DESTRUCTION,
)

logger = logging.getLogger(__name__)
# ============================================================================
# 围栏规则摘要文本（用于注入LLM Prompt）
# ============================================================================

_REDLINES_SUMMARY = """### 一、测试行为红线（绝对禁止）

1. **禁止修改真实数据** — 不得执行 UPDATE、DELETE、INSERT、DROP、TRUNCATE、ALTER 等会篡改数据的操作。
2. **禁止影响服务稳定性** — 不得发起任何可能导致拒绝服务（DoS）的扫描或攻击。
3. **禁止破坏生产环境文件** — 禁止覆盖、删除服务器上的任何文件。
4. **禁止篡改或删除真实用户数据** — 测试全程不允许修改或删除任何真实用户数据。
5. **禁止大规模遍历用户信息** — 严禁通过遍历方式批量获取用户列表或个人信息，单次查询结果不超过5条。
6. **禁止上传恶意代码** — 仅允许上传无害的纯文本证明文件（如内容为随机字符的1.php），禁止上传WebShell等恶意代码。
7. **禁止下载源码与敏感文件** — 禁止读取、下载服务器上的源代码、配置文件或敏感信息。
8. **禁止批量操作影响业务** — 避免批量提交留言、生成工单等对业务造成实际影响的行为。
9. **严格限定测试范围** — 仅测试授权范围内的系统，禁止对未授权系统进行测试。
10. **敏感信息读取上限** — 可获取敏感信息的漏洞，只需证明能够读取即可，实际读取的真实数据不得超过5组，严禁批量读取。
11. **越权测试账号要求** — 进行越权漏洞测试时，必须使用自行注册的两个测试账号完成验证，禁止操作他人账号。

### 二、无效漏洞类型（发现后应忽略，无需报告）

以下类型即使发现也应忽略，不视为有效产出：
1. URL跳转、前台个人弱口令、任意用户注册、Self-XSS、邮箱轰炸
2. 无法直接利用的数据或信息（无利用路径的内网信息、已过期密钥、无上下文孤立信息）
3. 拒绝服务类漏洞（DoS）
4. 非敏感信息泄露（已脱敏信息、公开文件、无有效数据的API接口泄露）
5. CORS跨域配置错误
6. CSRF及JSON Hijacking
"""

# ============================================================================
# 常量定义
# ============================================================================

# 危险SQL操作关键词
DANGEROUS_SQL_KEYWORDS: List[str] = [
    "UPDATE", "DELETE", "INSERT", "DROP", "TRUNCATE", "ALTER",
    "update", "delete", "insert", "drop", "truncate", "alter",
]

# 用户数据相关表名关键词
USER_DATA_TABLE_KEYWORDS: List[str] = [
    "user", "account", "member", "customer", "admin", "password",
    "email", "phone", "mobile", "profile", "个人信息", "用户",
    "账号", "账户", "会员",
]

# 无效漏洞类型关键词映射
INVALID_VULN_TYPE_MAP: Dict[str, str] = {
    # 低风险/无法利用
    "url_redirect": "URL跳转通常不被视为有效安全漏洞，需配合其他漏洞才能利用",
    "open_redirect": "开放重定向危害有限，通常不计入有效漏洞",
    "任意用户注册": "用户注册功能设计问题，除非可导致权限提升否则通常无效",
    "self-xss": "Self-XSS 需要用户自己攻击自己，不满足漏洞利用条件",
    "邮箱轰炸": "邮件轰炸属于业务逻辑问题，通常不计入有效安全漏洞",
    "弱口令": "弱密码属于配置管理问题，非应用程序漏洞",
    # 信息泄露(无利用路径)
    "内网信息泄露": "无具体利用路径的信息泄露通常不被视为有效漏洞",
    "过期密钥": "过期密钥如无法利用则不构成有效漏洞",
    # DoS
    "dos": "拒绝服务漏洞通常不被接受为有效漏洞",
    "拒绝服务": "DoS类漏洞在大多数漏洞评估中不予认可",
    # 已脱敏/公开
    "已脱敏": "已脱敏数据不构成敏感信息泄露",
    "公开文件": "公开可访问文件不构成安全漏洞",
    # CORS
    "cors": "CORS配置问题需结合实际利用场景判断",
    "跨域配置": "跨域配置问题通常不构成独立漏洞",
    # CSRF/JSON Hijacking
    "csrf": "CSRF漏洞在现代浏览器保护下危害有限",
    "json_hijacking": "JSON劫持在现代浏览器中已基本不可利用",
}

# WebShell特征
WEBSHELL_PATTERNS: List[str] = [
    r"<\?php\s+(system|exec|passthru|shell_exec|eval|assert)",
    r"<\?php\s+.*eval\s*\(",
    r"<%@\s+page.*import\s*=.*java\.io",
    r"<%\s*Runtime\.getRuntime\(\)\.exec",
    r"<\?php\s+.*`.*`",
    r"<\?php\s+.*\$_(GET|POST|REQUEST|COOKIE)\[.*\]\s*\(",
    r"eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
    r"<script\s+runat\s*=\s*['\"]server['\"]",
]

# 危险shell命令模式
DANGEROUS_SHELL_PATTERNS: List[Tuple[str, str, str]] = [
    # (模式, 规则ID, 描述)
    (r"rm\s+-rf?\s+/(?!\w)", "R03", "删除系统目录文件"),
    (r"rm\s+-rf?\s+/\w", "R03", "递归删除根目录下内容"),
    (r"dd\s+if=.*of=/dev/[sh]d", "R03", "使用dd破坏磁盘数据"),
    (r"dd\s+if=/dev/zero\s+of=", "R03", "使用dd填充零破坏数据"),
    (r">\s*/etc/\w", "R03", "重定向覆盖系统配置文件"),
    (r">\s*/proc/", "R03", "重定向覆盖proc文件系统"),
    (r"chmod\s+777\s+/etc", "R03", "chmod 777系统配置目录"),
    (r"chmod\s+777\s+/usr", "R03", "chmod 777系统程序目录"),
    (r"chmod\s+777\s+/var", "R03", "chmod 777系统数据目录"),
    (r"chmod\s+777\s+/bin", "R03", "chmod 777系统二进制目录"),
    (r"chmod\s+777\s+/sbin", "R03", "chmod 777系统管理目录"),
    (r"mkfs\.", "R03", "格式化文件系统"),
    (r"\bpvcreate\b", "R03", "创建物理卷"),
    (r"\bvgremove\b", "R03", "删除卷组"),
    (r":\(\)\s*\{\s*:\|:&\s*\};:", "R02", "Fork炸弹检测"),
    (r"while\s*\(\s*true\s*\)", "R02", "无限循环检测"),
    (r"while\s*:\s*;\s*do\s*:", "R02", "无限循环检测"),
    (r"for\s+.*\bin\s+.*\`seq", "R02", "大规模并发fork检测"),
]

# 敏感文件路径
SENSITIVE_FILE_PATTERNS: List[Tuple[str, str, str]] = [
    (r"\bdocker-compose", "R07", "Docker编排文件"),
]

# 批量操作关键词
BULK_OPERATION_KEYWORDS: List[str] = [
    "批量留言", "批量提交工单", "批量提交", "批量操作",
    "批量删除", "批量修改", "群发", "批量注册",
]

# 危险Python代码模式
DANGEROUS_PYTHON_PATTERNS: List[Tuple[str, str, str]] = [
    (r"os\.system\s*\(", "R01/R03", "调用os.system执行系统命令"),
    (r"subprocess\.(call|run|Popen)\s*\(", "R01/R03", "调用subprocess执行外部命令"),
    (r"open\s*\([^)]*['\"]w", "R01/R04", "打开文件进行写入操作"),
    (r"open\s*\([^)]*['\"]a", "R01/R04", "打开文件进行追加操作"),
    (r"os\.fork\s*\(", "R02", "fork进程可能导致资源耗尽"),
    (r"os\.kill\s*\(", "R03", "杀死系统进程"),
    (r"shutil\.rmtree\s*\(", "R03", "递归删除目录"),
    (r"os\.remove\s*\(", "R03", "删除文件"),
    (r"os\.rmdir\s*\(", "R03", "删除目录"),
    (r"os\.unlink\s*\(", "R03", "删除文件链接"),
    (r"while\s+True\s*:", "R02", "无限循环"),
    (r"while\s+1\s*:", "R02", "无限循环"),
    (r"requests\.(get|post)\s*\([^)]*\)\s*\.\s*text\b.*for\s+\w+\s+in\s+range\s*\(\s*\d{4,}\s*\)", "R02", "大规模HTTP请求循环"),
    (r"socket\.(socket|connect)\s*\(\s*\).*for\s+.*in\s+range\s*\(\s*\d{4,}\s*\)", "R02", "Socket泛洪攻击"),
]

# DoS检测阈值
DOS_BODY_SIZE_THRESHOLD: int = 10 * 1024 * 1024  # 10MB
DOS_CONCURRENT_PARAM_THRESHOLD: int = 1000  # 并发参数数量阈值

# 用户相关字段
USER_RELATED_FIELDS: List[str] = [
    "username", "user_name", "email", "phone", "mobile",
    "password", "passwd", "credit_card", "id_card", "身份证",
    "银行卡", "手机号", "姓名", "地址",
]


class TestingGuardrails:
    """
    渗透测试安全围栏.

    实现渗透测试的行为红线和无效漏洞类型过滤，防止危险操作
    破坏生产环境或泄露敏感数据。

    包含11条红线规则:
    - R01: 禁止修改真实数据 (UPDATE/DELETE/INSERT/DROP/TRUNCATE/ALTER)
    - R02: 禁止影响服务稳定性 (fork炸弹、无限循环、超高并发)
    - R03: 禁止破坏生产环境文件 (rm/dd/>覆盖/chmod 777系统路径)
    - R04: 禁止篡改真实用户数据
    - R05: 禁止大规模遍历用户信息 (LIMIT>5且SELECT用户相关字段)
    - R06: 禁止上传恶意代码 (webshell特征)
    - R07: 禁止下载源码与敏感文件
    - R08: 禁止批量操作影响业务
    - R09: 严格限定测试范围 (仅提醒)
    - R10: 敏感信息读取上限 (最多5组)
    - R11: 越权测试账号要求 (仅提醒)

    Attributes:
        max_sensitive_records: 敏感信息读取上限，默认5
        enabled: 是否启用围栏检查
        _sensitive_read_count: 已读取敏感信息计数
        _violations: 违规记录列表
    """

    def __init__(self, max_sensitive_records: int = 5, enabled: bool = True):
        """
        初始化安全围栏.

        Args:
            max_sensitive_records: 敏感信息读取上限，默认5
            enabled: 是否启用围栏检查，默认True
        """
        self.max_sensitive_records: int = max_sensitive_records
        self.enabled: bool = enabled
        self._sensitive_read_count: int = 0
        self._violations: List[GuardrailViolation] = []
        self._invalid_vulns_filtered: List[InvalidVulnType] = []

    def check_tool_call(
        self,
        tool_name: str,
        tool_params: Dict[str, Any],
    ) -> Tuple[bool, Optional[GuardrailViolation]]:
        """
        检查工具调用是否违反安全红线.

        根据工具类型调用相应的检查方法，检测危险命令、DoS模式、
        恶意代码等违规行为。

        Args:
            tool_name: 工具名称，如 'shell_exec', 'http_request', 'python_exec'
            tool_params: 工具参数字典

        Returns:
            Tuple[bool, Optional[GuardrailViolation]]: (是否通过检查, 违规记录)
            如果通过检查返回 (True, None)
            如果违规返回 (False, GuardrailViolation)
        """
        if not self.enabled:
            return True, None

        try:
            # 对 shell_exec 工具进行安全检查
            if tool_name == "shell_exec":
                command = tool_params.get("command", "")
                if isinstance(command, str) and command:
                    return self.check_shell_command(command)
                return True, None

            # 对 http_request 工具进行安全检查
            if tool_name == "http_request":
                return self._check_http_request(tool_params)

            # 对 python_exec 工具进行安全检查
            if tool_name == "python_exec":
                code = tool_params.get("code", "")
                if isinstance(code, str) and code:
                    return self._check_python_code(code)
                return True, None

            # 对 SQL 相关工具进行安全检查
            if tool_name in ("sqlmap_tool", "sql_inject", "sql_query"):
                payload = tool_params.get("payload", "") or tool_params.get("query", "")
                if isinstance(payload, str) and payload:
                    return self.check_sql_payload(payload)
                return True, None

            # 对文件操作工具进行安全检查
            if tool_name in ("file_read", "file_write", "file_upload", "file_download"):
                filepath = tool_params.get("path", "") or tool_params.get("filepath", "") or tool_params.get("url", "")
                operation = "read"
                if tool_name in ("file_write", "file_upload"):
                    operation = "write"
                elif tool_name == "file_download":
                    operation = "download"
                if isinstance(filepath, str) and filepath:
                    return self.check_file_operation(filepath, operation)
                return True, None

            return True, None

        except Exception as e:
            logger.warning(f"[guardrails] 工具调用检查异常: {e}")
            return True, None

    def check_shell_command(
        self,
        command: str,
    ) -> Tuple[bool, Optional[GuardrailViolation]]:
        """
        检查Shell命令是否违反安全红线.

        检测危险命令如 rm -rf, dd, >覆盖, chmod 777, fork炸弹等.

        Args:
            command: Shell命令字符串

        Returns:
            Tuple[bool, Optional[GuardrailViolation]]: (是否通过检查, 违规记录)
        """
        if not self.enabled:
            return True, None

        if not command or not isinstance(command, str):
            return True, None

        # 检查危险shell命令模式 (R02, R03)
        for pattern, rule_id, description in DANGEROUS_SHELL_PATTERNS:
            if re.search(pattern, command):
                violation = GuardrailViolation(
                    rule_id=rule_id,
                    rule_name=self._get_rule_name(rule_id),
                    severity="block",
                    tool_name="shell_exec",
                    details=f"检测到危险Shell命令 [{description}]: {command[:200]}",
                    suggested_action="请使用安全的替代命令，或联系管理员确认操作范围",
                )
                self._violations.append(violation)
                logger.warning(f"[guardrails] {rule_id} 违规: {description}")
                return False, violation

        # 检查敏感文件读取 (R07)
        if GUARDRAILS_BLOCK_FILE_DESTRUCTION:
            for pattern, rule_id, description in SENSITIVE_FILE_PATTERNS:
                if re.search(pattern, command):
                    violation = GuardrailViolation(
                        rule_id=rule_id,
                        rule_name=self._get_rule_name(rule_id),
                        severity="warn",
                        tool_name="shell_exec",
                        details=f"尝试访问敏感文件 [{description}]: {command[:200]}",
                        suggested_action="避免在生产环境中访问敏感系统文件",
                    )
                    self._violations.append(violation)
                    logger.warning(f"[guardrails] {rule_id} 警告: {description}")
                    return False, violation

        return True, None

    def _check_http_request(
        self,
        params: Dict[str, Any],
    ) -> Tuple[bool, Optional[GuardrailViolation]]:
        """
        检查HTTP请求参数是否违反DoS相关红线.

        检测超大body、大量并发参数等DoS模式.

        Args:
            params: HTTP请求参数字典

        Returns:
            Tuple[bool, Optional[GuardrailViolation]]: (是否通过检查, 违规记录)
        """
        if not GUARDRAILS_BLOCK_DOS:
            return True, None

        body = params.get("body", "")
        if body and isinstance(body, str):
            body_size = len(body.encode("utf-8"))
            if body_size > DOS_BODY_SIZE_THRESHOLD:
                violation = GuardrailViolation(
                    rule_id="R02",
                    rule_name=self._get_rule_name("R02"),
                    severity="block",
                    tool_name="http_request",
                    details=f"HTTP请求Body过大 ({body_size / 1024 / 1024:.1f}MB), "
                            f"超过阈值 {DOS_BODY_SIZE_THRESHOLD / 1024 / 1024}MB",
                    suggested_action="减小请求Body大小，避免DoS攻击",
                )
                self._violations.append(violation)
                logger.warning("[guardrails] R02 违规: HTTP请求Body过大")
                return False, violation

        # 检查大量并发参数
        query_params = params.get("params", {})
        if isinstance(query_params, dict) and len(query_params) > DOS_CONCURRENT_PARAM_THRESHOLD:
            violation = GuardrailViolation(
                rule_id="R02",
                rule_name=self._get_rule_name("R02"),
                severity="block",
                tool_name="http_request",
                details=f"HTTP请求参数数量过多 ({len(query_params)}), "
                        f"超过阈值 {DOS_CONCURRENT_PARAM_THRESHOLD}",
                suggested_action="减少请求参数数量，避免DoS攻击",
            )
            self._violations.append(violation)
            logger.warning("[guardrails] R02 违规: HTTP请求参数数量过多")
            return False, violation

        return True, None

    def _check_python_code(
        self,
        code: str,
    ) -> Tuple[bool, Optional[GuardrailViolation]]:
        """
        检查Python代码是否包含危险操作.

        检测 os.system, subprocess, open+write, fork等危险代码.

        Args:
            code: Python代码字符串

        Returns:
            Tuple[bool, Optional[GuardrailViolation]]: (是否通过检查, 违规记录)
        """
        if not code or not isinstance(code, str):
            return True, None

        for pattern, rule_id, description in DANGEROUS_PYTHON_PATTERNS:
            if re.search(pattern, code):
                violation = GuardrailViolation(
                    rule_id=rule_id.split("/")[0] if "/" in rule_id else rule_id,
                    rule_name=self._get_rule_name(rule_id.split("/")[0] if "/" in rule_id else rule_id),
                    severity="block",
                    tool_name="python_exec",
                    details=f"检测到危险Python代码 [{description}]: {code[:200]}",
                    suggested_action="请使用安全的替代方案，避免执行危险操作",
                )
                self._violations.append(violation)
                logger.warning(f"[guardrails] {rule_id} 违规: {description}")
                return False, violation

        # 检查SQL相关操作 (R01)
        if GUARDRAILS_BLOCK_DANGEROUS_SQL:
            for keyword in DANGEROUS_SQL_KEYWORDS:
                if re.search(rf"\b{keyword}\b", code, re.IGNORECASE):
                    violation = GuardrailViolation(
                        rule_id="R01",
                        rule_name=self._get_rule_name("R01"),
                        severity="block",
                        tool_name="python_exec",
                        details=f"Python代码中包含危险SQL操作 [{keyword}]: {code[:200]}",
                        suggested_action="禁止在代码中执行数据修改SQL操作",
                    )
                    self._violations.append(violation)
                    logger.warning(f"[guardrails] R01 违规: Python代码中的{keyword}")
                    return False, violation

        return True, None

    def check_sql_payload(
        self,
        payload: str,
    ) -> Tuple[bool, Optional[GuardrailViolation]]:
        """
        检测SQL payload中的危险操作.

        检测UPDATE/DELETE/INSERT/DROP/TRUNCATE/ALTER等危险SQL操作，
        以及大规模用户信息遍历 (R05).

        Args:
            payload: SQL payload字符串

        Returns:
            Tuple[bool, Optional[GuardrailViolation]]: (是否通过检查, 违规记录)
        """
        if not self.enabled:
            return True, None

        if not payload or not isinstance(payload, str):
            return True, None

        # 检查危险SQL关键词 (R01)
        if GUARDRAILS_BLOCK_DANGEROUS_SQL:
            for keyword in DANGEROUS_SQL_KEYWORDS:
                if re.search(rf"\b{keyword}\b", payload, re.IGNORECASE):
                    # R04: 检查是否是用户数据相关表
                    is_user_data = any(
                        re.search(rf"\b{table}\b", payload, re.IGNORECASE)
                        for table in USER_DATA_TABLE_KEYWORDS
                    )
                    rule_id = "R04" if is_user_data else "R01"
                    violation = GuardrailViolation(
                        rule_id=rule_id,
                        rule_name=self._get_rule_name(rule_id),
                        severity="block",
                        tool_name="sql_inject",
                        details=f"SQL payload包含危险操作 [{keyword}]" +
                                (f" 且涉及用户数据表" if is_user_data else "") +
                                f": {payload[:200]}",
                        suggested_action="仅允许执行SELECT查询，禁止数据修改操作",
                    )
                    self._violations.append(violation)
                    logger.warning(f"[guardrails] {rule_id} 违规: SQL {keyword}")
                    return False, violation

        # R05: 检查大规模用户信息遍历
        limit_match = re.search(r"LIMIT\s+(\d+)", payload, re.IGNORECASE)
        if limit_match:
            limit_value = int(limit_match.group(1))
            if limit_value > 5:
                has_user_fields = any(
                    re.search(rf"\b{field}\b", payload, re.IGNORECASE)
                    for field in USER_RELATED_FIELDS
                )
                if has_user_fields:
                    violation = GuardrailViolation(
                        rule_id="R05",
                        rule_name=self._get_rule_name("R05"),
                        severity="warn",
                        tool_name="sql_inject",
                        details=f"SQL查询LIMIT值过大({limit_value})且涉及用户敏感字段: {payload[:200]}",
                        suggested_action="限制LIMIT值不超过5，减少敏感信息暴露",
                    )
                    self._violations.append(violation)
                    logger.warning("[guardrails] R05 警告: 大规模用户信息遍历")
                    return False, violation

        return True, None

    def check_file_operation(
        self,
        filepath: str,
        operation: str = "read",
    ) -> Tuple[bool, Optional[GuardrailViolation]]:
        """
        检测文件操作是否违反安全红线.

        检测对敏感系统文件的访问、源码下载、webshell上传等.

        Args:
            filepath: 文件路径
            operation: 操作类型 ('read', 'write', 'upload', 'download')

        Returns:
            Tuple[bool, Optional[GuardrailViolation]]: (是否通过检查, 违规记录)
        """
        if not self.enabled:
            return True, None

        if not filepath or not isinstance(filepath, str):
            return True, None

        # R07: 检查敏感文件读取
        if operation in ("read", "download"):
            for pattern, rule_id, description in SENSITIVE_FILE_PATTERNS:
                if re.search(pattern, filepath):
                    violation = GuardrailViolation(
                        rule_id=rule_id,
                        rule_name=self._get_rule_name(rule_id),
                        severity="warn",
                        tool_name="file_read" if operation == "read" else "file_download",
                        details=f"尝试访问敏感文件 [{description}]: {filepath}",
                        suggested_action="避免访问系统敏感文件和源码",
                    )
                    self._violations.append(violation)
                    logger.warning(f"[guardrails] {rule_id} 警告: 访问{description}")
                    return False, violation

        # R06: 检查webshell上传
        if operation in ("write", "upload"):
            for pattern in WEBSHELL_PATTERNS:
                if re.search(pattern, filepath, re.IGNORECASE):
                    violation = GuardrailViolation(
                        rule_id="R06",
                        rule_name=self._get_rule_name("R06"),
                        severity="block",
                        tool_name="file_upload",
                        details=f"检测到WebShell特征: {filepath[:200]}",
                        suggested_action="禁止上传任何形式的恶意代码或WebShell",
                    )
                    self._violations.append(violation)
                    logger.warning("[guardrails] R06 违规: WebShell上传")
                    return False, violation

        # R03: 检查写入系统路径
        if operation in ("write", "upload") and GUARDRAILS_BLOCK_FILE_DESTRUCTION:
            if re.search(r"^/(etc|usr|bin|sbin|lib|proc|sys|dev)/", filepath):
                violation = GuardrailViolation(
                    rule_id="R03",
                    rule_name=self._get_rule_name("R03"),
                    severity="block",
                    tool_name="file_write",
                    details=f"禁止写入系统路径: {filepath}",
                    suggested_action="避免向系统目录写入文件",
                )
                self._violations.append(violation)
                logger.warning("[guardrails] R03 违规: 写入系统路径")
                return False, violation

        return True, None

    def is_invalid_vulnerability(
        self,
        vuln_type: str,
        description: str = "",
    ) -> Optional[InvalidVulnType]:
        """
        判断漏洞类型是否为无效漏洞.

        根据预定义的无效漏洞类型关键词进行匹配，判断该漏洞
        是否应被过滤不纳入报告。

        Args:
            vuln_type: 漏洞类型字符串
            description: 漏洞描述，用于辅助判断

        Returns:
            Optional[InvalidVulnType]: 如果为无效漏洞返回记录，否则返回None
        """
        if not vuln_type:
            return None

        vuln_type_lower = vuln_type.lower().strip()

        # 关键词匹配
        for invalid_key, reason in INVALID_VULN_TYPE_MAP.items():
            if invalid_key.lower() in vuln_type_lower or vuln_type_lower in invalid_key.lower():
                result = InvalidVulnType(
                    vuln_type=vuln_type,
                    reason=reason,
                    description=description,
                )
                self._invalid_vulns_filtered.append(result)
                logger.info(f"[guardrails] 无效漏洞过滤: {vuln_type} -> {reason}")
                return result

        # 检查"内网信息泄露"是否无利用路径
        if "内网" in vuln_type or "信息泄露" in description:
            if "利用" not in description and "路径" not in description:
                result = InvalidVulnType(
                    vuln_type=vuln_type,
                    reason=INVALID_VULN_TYPE_MAP["内网信息泄露"],
                    description=description,
                )
                self._invalid_vulns_filtered.append(result)
                return result

        # 检查"cors"关键词
        if "cors" in vuln_type_lower or "cross-origin" in vuln_type_lower:
            result = InvalidVulnType(
                vuln_type=vuln_type,
                reason=INVALID_VULN_TYPE_MAP["cors"],
                description=description,
            )
            self._invalid_vulns_filtered.append(result)
            return result

        # 检查"csrf"关键词
        if "csrf" in vuln_type_lower or "cross-site request forgery" in vuln_type_lower:
            result = InvalidVulnType(
                vuln_type=vuln_type,
                reason=INVALID_VULN_TYPE_MAP["csrf"],
                description=description,
            )
            self._invalid_vulns_filtered.append(result)
            return result

        # 检查"json hijacking"关键词
        if "json" in vuln_type_lower and "hijack" in vuln_type_lower:
            result = InvalidVulnType(
                vuln_type=vuln_type,
                reason=INVALID_VULN_TYPE_MAP["json_hijacking"],
                description=description,
            )
            self._invalid_vulns_filtered.append(result)
            return result

        return None

    def get_sensitive_read_count(self) -> int:
        """
        获取已读取敏感信息的次数.

        Returns:
            int: 当前敏感信息读取计数
        """
        return self._sensitive_read_count

    def record_sensitive_read(self, count: int = 1) -> bool:
        """
        记录敏感信息读取次数，检查是否超限.

        R10规则: 敏感信息读取上限为最多5组。

        Args:
            count: 本次读取的敏感信息数量，默认1

        Returns:
            bool: 如果未超限返回True，超限返回False
        """
        self._sensitive_read_count += count
        if self._sensitive_read_count > self.max_sensitive_records:
            logger.warning(
                f"[guardrails] R10 警告: 敏感信息读取次数({self._sensitive_read_count}) "
                f"超过上限({self.max_sensitive_records})"
            )
            return False
        return True

    def get_redlines_summary(self) -> str:
        """
        获取红线规则摘要，用于注入Prompt的中文规则摘要.

        返回11条红线规则的简洁中文描述，供LLM在规划时参考。

        Returns:
            str: 红线规则摘要文本
        """
        summary = """## 渗透测试安全红线规则 (必须严格遵守)

1. **R01-禁止修改真实数据**: 严禁执行 UPDATE/DELETE/INSERT/DROP/TRUNCATE/ALTER 等数据修改操作，仅限SELECT查询
2. **R02-禁止影响服务稳定性**: 严禁fork炸弹、无限循环、超高并发请求等可能导致服务不可用的操作
3. **R03-禁止破坏生产环境文件**: 严禁 rm -rf/dd/>覆盖/chmod 777 等破坏系统文件的操作
4. **R04-禁止篡改真实用户数据**: 严禁修改用户表(user/account/member等)中的任何数据
5. **R05-禁止大规模遍历用户信息**: 查询用户信息时LIMIT不得超过5，严禁批量导出用户数据
6. **R06-禁止上传恶意代码**: 严禁上传WebShell、后门脚本等恶意代码(<?php system/eval等)
7. **R07-禁止下载源码与敏感文件**: 严禁读取/etc/passwd、.env、.git、私钥等敏感文件
8. **R08-禁止批量操作影响业务**: 严禁批量留言、批量提交工单、批量注册等影响业务正常运行的操作
9. **R09-严格限定测试范围**: 仅在授权的目标URL/IP范围内进行测试，不得横向移动
10. **R10-敏感信息读取上限**: 最多读取5组敏感信息(密码/密钥/个人信息)，超限立即停止
11. **R11-越权测试账号要求**: 使用独立测试账号进行越权测试，不得使用真实用户账号

**违规后果**: 触发R01-R08将直接拦截操作并告警；R09-R11为提醒级别，需人工确认。"""
        return summary

    def _get_rule_name(self, rule_id: str) -> str:
        """
        根据规则ID获取规则名称.

        Args:
            rule_id: 规则编号，如 'R01'

        Returns:
            str: 规则名称
        """
        rule_names = {
            "R01": "禁止修改真实数据",
            "R02": "禁止影响服务稳定性",
            "R03": "禁止破坏生产环境文件",
            "R04": "禁止篡改真实用户数据",
            "R05": "禁止大规模遍历用户信息",
            "R06": "禁止上传恶意代码",
            "R07": "禁止下载源码与敏感文件",
            "R08": "禁止批量操作影响业务",
            "R09": "严格限定测试范围",
            "R10": "敏感信息读取上限",
            "R11": "越权测试账号要求",
        }
        return rule_names.get(rule_id, "未知规则")

    def get_violations(self) -> List[GuardrailViolation]:
        """
        获取所有违规记录.

        Returns:
            List[GuardrailViolation]: 违规记录列表
        """
        return self._violations.copy()

    def get_invalid_vulns_filtered(self) -> List[InvalidVulnType]:
        """
        获取所有被过滤的无效漏洞记录.

        Returns:
            List[InvalidVulnType]: 无效漏洞记录列表
        """
        return self._invalid_vulns_filtered.copy()

    def get_redlines_summary(self) -> str:
        """
        获取围栏规则摘要字符串.

        返回用于注入LLM系统提示的中文围栏规则摘要，
        包含所有测试行为红线和无效漏洞类型说明。

        Returns:
            中文围栏规则摘要字符串
        """
        return _REDLINES_SUMMARY

    def reset(self) -> None:
        """
        重置围栏状态.

        清除敏感信息读取计数和违规记录，重新开始计数。
        """
        self._sensitive_read_count = 0
        self._violations = []
        self._invalid_vulns_filtered = []
        logger.info("[guardrails] 围栏状态已重置")


# ============================================================================
# 模块级单例
# ============================================================================

_guardrails_instance: Optional[TestingGuardrails] = None


def get_guardrails() -> TestingGuardrails:
    """
    获取安全围栏单例实例.

    返回全局共享的 TestingGuardrails 实例，使用配置文件中的参数初始化。

    Returns:
        TestingGuardrails: 安全围栏实例

    Examples:
        >>> guardrails = get_guardrails()
        >>> passed, violation = guardrails.check_shell_command("rm -rf /")
        >>> assert passed == False
    """
    global _guardrails_instance
    if _guardrails_instance is None:
        _guardrails_instance = TestingGuardrails(
            max_sensitive_records=GUARDRAILS_MAX_SENSITIVE_RECORDS,
            enabled=GUARDRAILS_ENABLED,
        )
    return _guardrails_instance


def reset_guardrails() -> None:
    """
    重置安全围栏单例.

    清除全局围栏实例，下次调用 get_guardrails() 将创建新实例。
    """
    global _guardrails_instance
    _guardrails_instance = None
    logger.info("[guardrails] 单例已重置")
