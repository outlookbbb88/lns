# core/reflector.py

from datetime import datetime
from typing import Any, List, Dict, Optional
import json
import re
import time




def _get_console():
    """Lazy initialization of console to avoid circular imports."""
    from core.console import console_proxy
    return console_proxy
from llm.llm_client import LLMClient
from core.graph_manager import GraphManager
from rich.console import Console
from core.events import broker


def _normalize_audit_status(status: Any) -> str:
    """Normalize legacy audit status values into canonical lowercase values."""
    status_text = str(status or "").strip().lower()
    mapping = {
        "pass": "completed",
        "completed": "completed",
        "fail": "failed",
        "failed": "failed",
        "incomplete": "pending",
        "pending": "pending",
        "goal_achieved": "goal_achieved",
    }
    return mapping.get(status_text, "failed")


class Reflector:
    """
    反思器：负责复盘已完成的子任务，审核来自执行器的规划建议，
    并生成最终的、经过验证的图操作指令。

    该类实现了P-E-R架构中的反思功能，支持：
    - 子任务复盘：分析执行结果，验证产出物的有效性
    - 全局反思：对整个任务执行过程进行高层次总结
    - 情报生成：提取攻击情报和可操作的洞察
    - 上下文感知：整合历史反思记录和LLM推理过程

    Attributes:
        llm_client: LLM客户端实例，用于生成反思决策
        console: Rich控制台实例，用于格式化输出
        _run_log_path: 运行日志文件路径
        _log_dir: 日志目录路径
        _console_output_path: 控制台输出日志路径
    """

    def __init__(self, llm_client: LLMClient, output_mode: str = "default"):
        self.llm_client = llm_client
        self.output_mode = output_mode # Store output_mode
        self.console = Console()  # 初始化控制台实例用于格式化输出
        self._run_log_path = None
        self._log_dir = None

    def set_log_dir(self, log_dir: Optional[str]) -> None:
        """
        设置日志目录路径。

        Args:
            log_dir: 日志目录路径，如果为None则禁用日志记录

        Returns:
            None
        """
        import os

        self._log_dir = log_dir
        self._run_log_path = os.path.join(log_dir, "run_log.json") if log_dir else None
        self._console_output_path = os.path.join(log_dir, "console_output.log") if log_dir else None

    def _generate_reflector_prompt(
        self,
        subtask_goal: str,
        status: str,
        execution_log: str,
        staged_causal_nodes: List[Dict],
        causal_graph_summary: str,
        completion_criteria: str,
        dependency_context: Optional[List[Dict]] = None,
        failure_patterns_summary: Dict[str, Any] = None,
        *,
        reflector_context=None,
    ) -> str:
        """
        使用PromptManager生成反思器提示词（已迁移到新模板系统）。

        Args:
            subtask_goal: 子任务目标描述
            status: 子任务执行状态
            execution_log: 执行日志
            staged_causal_nodes: 暂存的因果节点列表
            causal_graph_summary: 因果图摘要
            completion_criteria: 完成标准
            dependency_context: 依赖上下文（可选）
            failure_patterns_summary: 失败模式摘要（可选）
            reflector_context: 反思上下文对象（可选）

        Returns:
            str: 格式化后的反思器提示词字符串
        """
        from core.prompts import PromptManager

        manager = PromptManager()

        # 构建subtask对象
        subtask = {"description": subtask_goal, "completion_criteria": completion_criteria}

        # 构建context
        context = {
            "causal_graph_summary": causal_graph_summary or "因果链图谱为空。",
            "dependency_context": dependency_context or [],
            "failure_patterns": failure_patterns_summary,
        }

        # 使用PromptManager生成提示词
        prompt = manager.build_reflector_prompt(
            subtask=subtask,
            status=status,
            execution_log=execution_log,
            staged_causal_nodes=staged_causal_nodes,
            context=context,
            reflector_context=reflector_context,
        )

        return prompt

    def _generate_reflection_context_section(self, reflector_context) -> str:
        """
        生成反思上下文摘要部分。

        整合已验证模式、持久性洞察、相关反思历史和LLM反思记录，
        形成完整的反思上下文摘要。

        Args:
            reflector_context: 反思上下文对象，包含历史反思和LLM推理信息

        Returns:
            str: 格式化的反思上下文摘要字符串
        """

        # 生成已验证模式摘要
        validated_patterns_summary = self._generate_validated_patterns_summary(reflector_context)

        # 生成持久性洞察摘要
        persistent_insights_summary = self._generate_persistent_insights_summary(reflector_context)

        # 生成相关反思历史
        relevant_reflection_log = self._generate_relevant_reflection_history(reflector_context)

        # 生成完整LLM反思记录摘要
        llm_reflection_summary = self._generate_llm_reflection_summary(reflector_context)

        context_section = f"""
## 历史反思上下文（增强版）

### 已验证的有效模式
{validated_patterns_summary}

### 持久性技术洞察
{persistent_insights_summary}

### 相关历史反思
{relevant_reflection_log}

### 完整LLM反思记录
{llm_reflection_summary}
"""
        return context_section

    def _generate_validated_patterns_summary(self, reflector_context) -> str:
        """
        生成已验证模式摘要。

        Args:
            reflector_context: 反思上下文对象

        Returns:
            str: 已验证的有效模式列表的格式化字符串
        """
        if not reflector_context.validated_patterns:
            return "暂无已验证的有效模式"

        summary = []
        for pattern in reflector_context.validated_patterns[-5:]:  # 最近5个模式
            summary.append(
                f"- {pattern.get('pattern_type', '未知模式')}: {pattern.get('description', '无描述')} "
                f"(置信度: {pattern.get('confidence', 0.0):.1f})"
            )
        return "\n".join(summary)

    def _generate_persistent_insights_summary(self, reflector_context) -> str:
        """
        生成持久性技术洞察摘要。

        Args:
            reflector_context: 反思上下文对象

        Returns:
            str: 持久性技术洞察列表的格式化字符串
        """
        if not reflector_context.persistent_insights:
            return "暂无持久性技术洞察"

        return "\n".join(
            [
                f"- {insight.get('insight_type', '未知洞察')}: {insight.get('description', '无描述')}"
                for insight in reflector_context.persistent_insights[-3:]
            ]
        )

    def _generate_relevant_reflection_history(self, reflector_context) -> str:
        """
        生成相关历史反思记录。

        Args:
            reflector_context: 反思上下文对象

        Returns:
            str: 最近3次反思尝试的摘要字符串
        """
        if not reflector_context.reflection_log:
            return "无历史反思记录"

        summary = []
        for reflection in reflector_context.reflection_log:
            ts = getattr(reflection, "timestamp", 0) or 0
            sub_id = getattr(reflection, "subtask_id", "未知任务")
            key_insight = getattr(reflection, "key_insight", "")
            rep = getattr(reflection, "full_reflection_report", None)
            status = None
            finding = None
            action = None
            artifacts_count = None
            if isinstance(rep, dict):
                audit = rep.get("audit_result", {})
                status = audit.get("status")
                kfs = rep.get("key_findings")
                if isinstance(kfs, list) and kfs:
                    finding = kfs[0] if isinstance(kfs[0], str) else str(kfs[0])
                intel = rep.get("attack_intelligence", {})
                acts = intel.get("actionable_insights")
                if isinstance(acts, list) and acts:
                    action = acts[0]
                # 验证节点信息（替代旧的validated_artifacts）
                nodes = rep.get("validated_nodes")
                if isinstance(nodes, list):
                    artifacts_count = len(nodes)
            timestamp = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
            parts = [f"- {timestamp}: {sub_id}"]
            if status:
                parts.append(f"状态: {status}")
            if key_insight:
                parts.append(f"洞察: {key_insight}")
            if finding:
                parts.append(f"发现: {finding}")
            if action:
                parts.append(f"建议: {action}")
            if artifacts_count is not None:
                parts.append(f"产出物: {artifacts_count}")
            summary.append(" | ".join(parts))
        return "\n".join(summary)

    def _extract_audit_summary(self, audit_result: dict, summary: list) -> None:
        """
        从审计结果中提取关键信息到摘要。

        Args:
            audit_result: 审计结果字典
            summary: 摘要列表，用于附加提取的信息
        """
        if not audit_result:
            return

        status = audit_result.get("status", "unknown")
        completion = audit_result.get("completion_check", "")
        strategic_failure = audit_result.get("is_strategic_failure", False)

        summary.append(f"审计状态: {status}")
        if completion:
            completion_preview = completion[:100] + "..." if len(completion) > 100 else completion
            summary.append(f"完成度检查: {completion_preview}")
        if strategic_failure:
            summary.append("战略性失败: 是")

        methodology_issues = audit_result.get("methodology_issues", [])
        if methodology_issues:
            issues_summary = ", ".join(
                [f"{issue[:30]}..." if len(issue) > 30 else issue for issue in methodology_issues[:2]]
            )
            if len(methodology_issues) > 2:
                issues_summary += f" 等{len(methodology_issues)}个方法论问题"
            summary.append(f"方法论问题: {issues_summary}")

        logic_issues = audit_result.get("logic_issues", [])
        if logic_issues:
            logic_summary = ", ".join([f"{issue[:30]}..." if len(issue) > 30 else issue for issue in logic_issues[:2]])
            if len(logic_issues) > 2:
                logic_summary += f" 等{len(logic_issues)}个逻辑问题"
            summary.append(f"逻辑问题: {logic_summary}")

    def _extract_attack_intelligence(self, attack_intelligence: dict, summary: list) -> None:
        """
        从政击情报中提取可执行洞察。

        Args:
            attack_intelligence: 攻击情报字典
            summary: 摘要列表，用于附加提取的信息
        """
        if not attack_intelligence:
            return

        actionable_insights = attack_intelligence.get("actionable_insights", [])
        if actionable_insights:
            insights_summary = ", ".join(
                [f"{insight[:40]}..." if len(insight) > 40 else insight for insight in actionable_insights[:2]]
            )
            if len(actionable_insights) > 2:
                insights_summary += f" 等{len(actionable_insights)}个可执行洞察"
            summary.append(f"攻击情报: {insights_summary}")

    def _extract_key_facts(self, key_facts: list, summary: list) -> None:
        """
        从关键事实列表中提取摘要。

        Args:
            key_facts: 关键事实列表
            summary: 摘要列表，用于附加提取的信息
        """
        if not key_facts:
            return

        facts_summary = ", ".join([f"{fact[:50]}..." if len(fact) > 50 else fact for fact in key_facts[:3]])
        if len(key_facts) > 3:
            facts_summary += f" 等{len(key_facts)}个关键事实"
        summary.append(f"关键事实: {facts_summary}")

    def _extract_causal_updates(self, causal_updates: dict, summary: list) -> None:
        """
        提取因果图更新类型。

        Args:
            causal_updates: 因果图更新字典
            summary: 摘要列表，用于附加提取的信息
        """
        if not causal_updates:
            return

        update_types = list(causal_updates.keys())
        summary.append(f"因果图更新类型: {', '.join(update_types)}")

    def _extract_prompt_context(self, llm_reflection_prompt: str, summary: list) -> None:
        """
        从LLM反思提示词中提取角色和核心职责。

        Args:
            llm_reflection_prompt: LLM反思提示词字符串
            summary: 摘要列表，用于附加提取的信息
        """
        if not llm_reflection_prompt:
            return

        role_match = re.search(r"# 角色: ([^\n]+)", llm_reflection_prompt)
        if role_match:
            summary.append(f"反思角色: {role_match.group(1)}")

        duties_match = re.search(r"## 核心职责\\s+([^#]+)", llm_reflection_prompt, re.DOTALL)
        if duties_match:
            duties = duties_match.group(1).strip()
            duties_preview = duties[:100] + "..." if len(duties) > 100 else duties
            summary.append(f"核心职责: {duties_preview}")

    def _extract_response_content(self, resp_text: str, summary: list) -> None:
        """
        从LLM反思响应中提取结构化内容。

        Args:
            resp_text: LLM反思响应文本
            summary: 摘要列表，用于附加提取的信息
        """
        try:
            resp_data = json.loads(resp_text)
            if isinstance(resp_data, dict):
                audit_result = resp_data.get("audit_result", {})
                if audit_result:
                    status = audit_result.get("status", "unknown")
                    summary.append(f"响应状态: {status}")

                    recommendations = resp_data.get("recommendations", [])
                    if recommendations:
                        rec_summary = ", ".join(
                            [rec[:50] + "..." if len(rec) > 50 else rec for rec in recommendations[:2]]
                        )
                        summary.append(f"关键建议: {rec_summary}")
        except json.JSONDecodeError:
            # 如果不是JSON，提取文本中的关键信息
            lines = resp_text.split("\n")
            key_lines = [
                line
                for line in lines
                if any(
                    keyword in line
                    for keyword in [
                        "漏洞",
                        "漏洞",
                        "vulnerability",
                        "Vulnerability",
                        "建议",
                        "recommendation",
                        "Recommendation",
                    ]
                )
            ]
            if key_lines:
                key_info = "; ".join([line[:80] + "..." if len(line) > 80 else line for line in key_lines[:3]])
                summary.append(f"响应关键信息: {key_info}")

    def _generate_llm_reflection_summary(self, reflector_context) -> str:
        """
        生成完整LLM反思记录摘要。

        Args:
            reflector_context: 反思上下文对象，包含LLM推理历史

        Returns:
            LLM输入提示词、输出响应和推理过程的格式化摘要
        """
        if not reflector_context.reflection_log:
            return "暂无LLM反思记录"

        # 获取最近的反思记录
        latest_reflection = reflector_context.reflection_log[-1]
        summary = []

        # 提取关键信息：从完整反思报告中提取核心洞察
        if hasattr(latest_reflection, "full_reflection_report") and latest_reflection.full_reflection_report:
            rep = latest_reflection.full_reflection_report
            if isinstance(rep, dict):
                self._extract_audit_summary(rep.get("audit_result", {}), summary)
                self._extract_attack_intelligence(rep.get("attack_intelligence", {}), summary)
                self._extract_key_facts(rep.get("key_facts", []), summary)
                self._extract_causal_updates(rep.get("causal_graph_updates", {}), summary)

        # 优化LLM反思提示词摘要 - 提取角色和核心职责
        if hasattr(latest_reflection, "llm_reflection_prompt") and latest_reflection.llm_reflection_prompt:
            self._extract_prompt_context(latest_reflection.llm_reflection_prompt, summary)

        # 优化LLM反思响应摘要 - 提取结构化响应内容
        if hasattr(latest_reflection, "llm_reflection_response") and latest_reflection.llm_reflection_response:
            self._extract_response_content(latest_reflection.llm_reflection_response, summary)

        return " | ".join(summary) if summary else "LLM反思记录详情待完善"

    def _normalize_dependency_context(self, dependency_context: Optional[List[Dict]], subtask_data: Dict) -> Optional[List[Dict]]:
        termination_reason = subtask_data.get("termination_reason")
        executed_steps = subtask_data.get("executed_steps")
        if dependency_context and isinstance(dependency_context, list):
            dependency_context = [
                item for item in dependency_context if not (isinstance(item, dict) and "termination_reason" in item)
            ]
        if termination_reason:
            dependency_context = dependency_context or []
            dependency_context.append(
                {
                    "termination_reason": termination_reason,
                    "executed_steps": executed_steps,
                    "source": "normalized",
                }
            )
        return dependency_context

    async def _evaluate_success_with_llm(self, completion_criteria: str, execution_log: str) -> bool:
        """
        使用LLM来验证任务是否成功，取代固定的正则表达式。

        Args:
            completion_criteria: 任务的自然语言完成标准。
            execution_log: 执行器的输出日志。

        Returns:
            bool: 如果LLM判断任务已成功，则返回True，否则返回False。
        """
        if not completion_criteria or not execution_log:
            return False

        try:
            prompt = f"""你是一位严格的渗透测试结果审计员。
- 任务的完成标准是："{completion_criteria}"
- 执行日志和结果如下："{execution_log}"

基于上述日志，请判断完成标准是否已明确且无歧义地达成？
仅回答 "true" 或 "false"。
"""
            messages = [{"role": "user", "content": prompt}]
            
            # 使用一个专用的、轻量级的验证角色
            response, _ = await self.llm_client.send_message(messages, role="reflector_validator")
            
            # 解析LLM的布尔值响应
            result_str = str(response).strip().lower()
            _get_console().print(f"🕵️  基于LLM的验证返回: [cyan]'{result_str}'[/cyan]", style="dim")
            return result_str == "true"
            
        except Exception as e:
            _get_console().print(f"⚠️ 基于LLM的验证失败: {e}", style="yellow")
            return False


    async def reflect(
        self,
        subtask_id: str,  # Add subtask_id as a parameter
        subtask_data: Dict,
        status: str,
        execution_log: str,
        proposed_changes: List[Dict],
        staged_causal_nodes: List[Dict],
        causal_graph_summary: str,
        dependency_context: Optional[List[Dict]] = None,
        graph_manager=None,  # Add graph_manager to access causal graph analysis
        reflector_context=None,  # 新增：Reflector上下文对象
    ) -> Dict:
        """
        执行反思与审核。

        该函数实现了反思器的核心功能，包括：
        - 分析子任务执行结果和状态
        - 验证产出物的有效性和完整性
        - 生成攻击情报和可操作的洞察
        - 提供因果图更新建议
        - 支持失败模式分析和上下文感知

        Args:
            subtask_id: 子任务ID
            subtask_data: 子任务数据字典
            status: 子任务执行状态
            execution_log: 执行日志
            proposed_changes: 提议的变更列表
            staged_causal_nodes: 暂存的因果节点列表
            causal_graph_summary: 因果图摘要
            long_mem: 长期记忆对象（可选）
            dependency_context: 依赖上下文（可选）
            graph_manager: 图管理器实例（可选）
            reflector_context: 反思上下文对象（可选）

        Returns:
            反思结果字典，包含审核结果、情报摘要、指标等
        """
        subtask_goal = subtask_data.get("id", subtask_id)
        completion_criteria = subtask_data.get("completion_criteria", "No specific criteria defined.")

        failure_patterns_summary = {}
        if graph_manager:
            failure_patterns_summary = graph_manager.analyze_failure_patterns()

        dependency_context = self._normalize_dependency_context(dependency_context, subtask_data)
        prompt = self._generate_reflector_prompt(
            subtask_goal,
            status,
            execution_log,
            staged_causal_nodes,
            causal_graph_summary,
            completion_criteria,
            dependency_context,
            failure_patterns_summary,
            reflector_context=reflector_context,
        )
        messages = [{"role": "user", "content": prompt}]

        try:
            reflection_data, call_metrics = await self.llm_client.send_message(messages, role="reflector")
            if not reflection_data:
                raise ValueError("LLM returned no data for reflection.")

            reflection_data["metrics"] = call_metrics
            reflection_data["llm_reflection_prompt"] = prompt

            audit_result = reflection_data.get("audit_result", {})
            if not isinstance(audit_result, dict):
                audit_result = {}
                reflection_data["audit_result"] = audit_result
            normalized_status = _normalize_audit_status(audit_result.get("status"))
            audit_result["status"] = normalized_status

            # 直接采用LLM的判断结果，由Planner决定任务是否已完成
            llm_reported_status = normalized_status
            _get_console().print(f"🤖 LLM reported status: [bold green]{llm_reported_status}[/bold green]. Directly adopting LLM judgment.", style="dim")

            # 保持对 validated_nodes 的引用，因为它们可能包含除目标产物之外的其他有用证据
            reflection_data.setdefault("causal_graph_updates", {})

            # 新增：无效漏洞类型过滤
            from core.guardrails import get_guardrails
            from conf.config import GUARDRAILS_ENABLED

            guardrails = get_guardrails()
            if GUARDRAILS_ENABLED:
                filtered_invalid = []
                # 检查 causal_graph_updates 中的 nodes
                cg_updates = reflection_data.get("causal_graph_updates", {})
                if cg_updates and "nodes" in cg_updates:
                    valid_nodes = []
                    for node in cg_updates["nodes"]:
                        node_type = node.get("node_type", "")
                        if node_type in ("Vulnerability", "ConfirmedVulnerability"):
                            vuln_type = node.get("vulnerability", node.get("exploit_type", ""))
                            description = node.get("description", "")
                            invalid = guardrails.is_invalid_vulnerability(vuln_type, description)
                            if invalid:
                                filtered_invalid.append({
                                    "node_id": node.get("id", "unknown"),
                                    "vuln_type": vuln_type,
                                    "reason": invalid.reason if hasattr(invalid, 'reason') else str(invalid)
                                })
                                continue  # 过滤掉无效漏洞
                        valid_nodes.append(node)
                    cg_updates["nodes"] = valid_nodes

                # 记录被过滤的无效漏洞
                if filtered_invalid:
                    reflection_data["filtered_invalid_vulnerabilities"] = filtered_invalid
                    _get_console().print(
                        f"[Guardrails] 过滤了 {len(filtered_invalid)} 个无效漏洞类型",
                        style="bold yellow"
                    )
            
            # --- VETO LOGIC START ---
            rejected_nodes = reflection_data.get("rejected_staged_nodes", [])
            if rejected_nodes and graph_manager:
                _get_console().print(f"🚫 Reflector exercising VETO power on {len(rejected_nodes)} nodes: {rejected_nodes}", style="bold red")
                for node_id in rejected_nodes:
                    # Remove from graph
                    if graph_manager.graph.has_node(node_id):
                         graph_manager.delete_node(node_id)
                    # Also need to remove from causal_graph_updates if present to prevent re-addition
                    updates = reflection_data.get("causal_graph_updates", {})
                    if "nodes" in updates:
                        updates["nodes"] = [n for n in updates["nodes"] if n.get("id") != node_id]
                    # Also remove edges involving this node
                    if "edges" in updates:
                        updates["edges"] = [e for e in updates["edges"] if e.get("source_id") != node_id and e.get("target_id") != node_id]
            # --- VETO LOGIC END ---

            # 新增：钉钉漏洞推送 —— 当确认漏洞时立即推送并停止测试
            if graph_manager:
                await self._notify_dingtalk_from_graph(graph_manager)

            try:
                import os

                op_id = os.path.basename(self._log_dir) if self._log_dir else None
                await broker.emit("reflection.completed", {"subtask_id": subtask_id}, op_id=op_id)
            except Exception:
                pass
            return reflection_data

        except (json.JSONDecodeError, ValueError) as e:
            # 记录异常到 console_output.log
            if hasattr(self, "_console_output_path") and self._console_output_path:
                try:
                    with open(self._console_output_path, "a", encoding="utf-8") as f:
                        f.write(f"[ERROR] Reflector异常: {type(e).__name__}: {e}\n")
                except Exception:
                    pass
            print(f"解析Reflector输出失败: {e}")
            try:
                import os

                op_id = os.path.basename(self._log_dir) if self._log_dir else None
                await broker.emit("reflection.completed", {"subtask_id": subtask_id, "error": str(e)}, op_id=op_id)
            except Exception:
                pass
            return {
                "audit_result": {
                    "status": "failed",
                    "completion_check": "解析失败",
                    "logic_issues": [str(e)],
                    "methodology_issues": [],
                },
                "key_findings": [],
                "validated_nodes": [],
                "insight": None,
                "causal_graph_updates": {},
                "metrics": None,
            }

    def _extract_vulnerability_info(self, vuln_node: dict, execution_log: str) -> dict:
        """
        从漏洞节点和执行日志中提取完整的漏洞信息。

        智能提取策略：
        1. 从节点字段直接提取（如果存在）
        2. 从执行日志中解析工具调用提取 PoC / 证据
        3. 从 description / exploit_type / 节点 ID 推断漏洞类型和标题
        4. 生成有针对性的修复建议

        Args:
            vuln_node: 因果图中的漏洞节点
            execution_log: 执行日志（用于补充PoC和证据）

        Returns:
            结构化的漏洞信息字典
        """
        # ---- 1. 提取基础字段 ----
        description = vuln_node.get("description", "")
        node_id = vuln_node.get("id", "")

        # 漏洞类型：exploit_type > 从description推断 > 从node_id推断 > 未知
        vuln_type = vuln_node.get("exploit_type", "")
        if not vuln_type:
            vuln_type = self._infer_vuln_type_from_text(description, node_id)

        # 标题：title > 用漏洞类型+描述生成
        title = vuln_node.get("title", "")
        if not title:
            title = self._generate_title(vuln_type, description, node_id)

        # 严重程度
        severity = self._classify_severity(vuln_node.get("cvss_score", 0), vuln_type)

        # 影响URL
        affected_url = vuln_node.get("affected_url", vuln_node.get("host", vuln_node.get("target_url", "")))
        if not affected_url and execution_log:
            affected_url = self._extract_target_url(execution_log)

        # ---- 2. 提取 PoC（优先顺序）----
        poc = self._extract_poc(vuln_node, execution_log)

        # ---- 3. 提取证据 ----
        evidence = self._extract_evidence(vuln_node, execution_log)

        # ---- 4. 构建复现步骤 ----
        reproduction_steps = self._build_reproduction_steps(vuln_node, execution_log, affected_url)

        # ---- 5. 修复建议 ----
        remediation = vuln_node.get("remediation", "")
        if not remediation:
            remediation = self._generate_remediation_advice(vuln_type)

        return {
            "title": title,
            "vuln_type": vuln_type,
            "severity": severity,
            "description": description or f"发现 {vuln_type} 类型漏洞",
            "affected_url": affected_url,
            "poc": poc,
            "evidence": evidence,
            "reproduction_steps": reproduction_steps,
            "remediation": remediation,
            "discovered_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------
    # 以下辅助方法用于智能提取漏洞信息
    # ------------------------------------------------------------------

    def _generate_title(self, vuln_type: str, description: str, node_id: str) -> str:
        """根据漏洞类型和描述生成标题"""
        type_names = {
            "sql_injection": "SQL注入", "xss": "XSS跨站脚本", "rce": "远程代码执行",
            "ssrf": "SSRF服务器端请求伪造", "csrf": "CSRF跨站请求伪造",
            "lfi": "LFI本地文件包含", "rfi": "RFI远程文件包含",
            "file_upload": "任意文件上传", "auth_bypass": "认证绕过",
            "insecure_deserialization": "不安全的反序列化",
            "directory_traversal": "目录遍历", "command_injection": "命令注入",
            "xxe": "XXE XML外部实体", "open_redirect": "URL跳转",
            "info_leak": "信息泄露", "weak_password": "弱口令",
            "user_enumeration": "用户枚举", "shiro_deserialization": "Shiro反序列化",
            "jwt_bypass": "JWT认证绕过", "path_traversal": "路径遍历",
            "idac": "越权访问", "sensitive_data_exposure": "敏感数据泄露",
            "default_credentials": "默认凭据", "brute_force": "暴力破解",
        }
        cn_type = type_names.get(vuln_type.lower(), vuln_type)

        # 从描述中提取关键短语作为标题
        if description:
            # 取描述的前30个字符或第一个句号前
            short_desc = description.split("。")[0].split("，")[0].strip()
            if len(short_desc) > 5:
                return f"{cn_type}漏洞 - {short_desc[:40]}"

        # 从node_id提取线索
        if node_id:
            for keyword, name in type_names.items():
                if keyword.replace("_", "") in node_id.lower():
                    return f"{name}漏洞"

        return f"{cn_type}漏洞"

    def _classify_severity(self, cvss_score: Any, vuln_type: str) -> str:
        """根据CVSS评分和漏洞类型判断严重程度"""
        # 有CVSS评分时优先使用
        if cvss_score and isinstance(cvss_score, (int, float)):
            if cvss_score >= 9.0:
                return "严重"
            elif cvss_score >= 7.0:
                return "高危"
            elif cvss_score >= 4.0:
                return "中危"
            elif cvss_score > 0:
                return "低危"

        # 无CVSS时根据漏洞类型推断
        critical_types = {"rce", "command_injection", "sql_injection", "auth_bypass",
                          "insecure_deserialization", "shiro_deserialization", "file_upload_rce"}
        high_types = {"xss", "ssrf", "file_upload", "lfi", "info_leak_sensitive",
                      "jwt_bypass", "sensitive_data_exposure", "user_enumeration"}
        medium_types = {"csrf", "open_redirect", "directory_traversal", "weak_password",
                        "default_credentials", "user_enumeration"}

        vt_lower = vuln_type.lower().replace(" ", "_")
        if vt_lower in critical_types:
            return "严重"
        elif vt_lower in high_types:
            return "高危"
        elif vt_lower in medium_types:
            return "中危"
        # 未知类型默认 INFO，避免信息收集类发现被误判为高危
        return "信息"

    def _infer_vuln_type_from_text(self, description: str, node_id: str = "") -> str:
        """从描述文本中推断漏洞类型。优先级: description > node_id"""
        desc_lower = description.lower() if description else ""
        id_lower = node_id.lower() if node_id else ""

        # description 中的关键词优先级更高（放前面）
        # node_id 中的关键词容易误判（如 shiro_test_1 中的 "shiro"）
        desc_priority_patterns = [
            ("user_enumeration", ["用户枚举", "username enumeration", "枚举用户", "用户名枚举"]),
            ("sql_injection", ["sql注入", "sql injection", "盲注", "报错注入", "延时注入", "union注入", "堆叠注入", "注入点", "注入漏洞"]),
            ("xss", ["xss", "跨站脚本", "cross.site.script", "反射型xss", "存储型xss", "dom型xss"]),
            ("rce", ["远程代码执行", "rce", "remote code execution", "代码执行"]),
            ("command_injection", ["命令注入", "command injection", "命令执行"]),
            ("ssrf", ["ssrf", "服务器端请求伪造", "server.side.request.forgery"]),
            ("csrf", ["csrf", "跨站请求伪造", "cross.site.request.forgery"]),
            ("lfi", ["lfi", "本地文件包含", "local file inclusion"]),
            ("rfi", ["rfi", "远程文件包含", "remote file inclusion"]),
            ("file_upload", ["文件上传", "file upload", "任意文件上传", "上传漏洞"]),
            ("auth_bypass", ["认证绕过", "auth bypass", "未授权访问", "越权访问", "垂直越权", "水平越权"]),
            ("xxe", ["xxe", "xml外部实体", "xml external entity"]),
            ("directory_traversal", ["目录遍历", "directory traversal", "路径穿越"]),
            ("path_traversal", ["路径遍历", "path traversal"]),
            ("info_leak", ["信息泄露", "源码泄露", "配置文件泄露", "目录列表", "info leak", "git泄露", "svn泄露"]),
            ("weak_password", ["弱口令", "weak password", "默认密码"]),
            ("open_redirect", ["url跳转", "open redirect", "任意跳转", "未授权跳转"]),
            ("jwt_bypass", ["jwt", "json web token", "token伪造", "token绕过"]),
            ("sensitive_data_exposure", ["敏感数据泄露", "敏感信息泄露", "个人信息泄露", "数据泄露"]),
            ("default_credentials", ["默认凭据", "默认账号", "默认口令"]),
            ("idac", ["id越权", "越权"]),
        ]

        # 第一轮：从 description 推断（高优先级、精确匹配）
        for vuln_type, keywords in desc_priority_patterns:
            for kw in keywords:
                if kw.lower() in desc_lower:
                    return vuln_type

        # 第二轮：从 description 推断通用类型
        if "反序列化" in description or "deserialization" in desc_lower:
            return "insecure_deserialization"
        if "shiro" in desc_lower:
            return "shiro_deserialization"

        # 第三轮：从 node_id 推断（仅在 description 为空或无法推断时使用）
        # 注意：更具体的类型放在前面（如 shiro_deserialization 在 insecure_deserialization 之前）
        id_patterns = [
            ("sql_injection", ["sql", "sqli", "injection"]),
            ("xss", ["xss", "cross_site"]),
            ("rce", ["rce", "remote_code"]),
            ("ssrf", ["ssrf"]),
            ("file_upload", ["upload", "fileupload"]),
            ("auth_bypass", ["auth", "bypass", "unauth"]),
            ("lfi", ["lfi", "file_include"]),
            ("shiro_deserialization", ["shiro"]),
            ("insecure_deserialization", ["deserialize", "serialization"]),
            ("user_enumeration", ["user_enum", "enum_user"]),
            ("directory_traversal", ["traversal", "directory"]),
            ("info_leak", ["info_leak", "leak"]),
        ]
        for vuln_type, keywords in id_patterns:
            for kw in keywords:
                if kw.lower() in id_lower:
                    return vuln_type

        return "未知类型"

    def _extract_poc(self, vuln_node: dict, execution_log: str) -> str:
        """提取完整PoC：节点字段 > 执行日志 > 默认"""
        # 1. 从节点字段提取
        poc_parts = []
        exploit_payload = vuln_node.get("exploit_payload", "")
        if exploit_payload:
            poc_parts.append(f"[Exploit Payload]\n{exploit_payload}")

        known_exploits = vuln_node.get("known_exploits", [])
        if known_exploits:
            poc_parts.extend(known_exploits)

        # 2. 从执行日志提取工具调用
        if execution_log:
            log_poc = self._extract_poc_from_execution_log(execution_log)
            if log_poc:
                poc_parts.append(log_poc)

        if poc_parts:
            return "\n\n".join(poc_parts)

        return "PoC 提取失败，请查看完整执行日志"

    def _extract_poc_from_execution_log(self, execution_log: str) -> str:
        """从执行日志中提取关键的工具调用 payload 作为 PoC"""
        import re

        poc_blocks = []

        # 提取 http_request 的 payload
        # 提取 http_request 调用（兼容转义引号）
        http_pattern = r'"tool"\s*:\s*"http_request"'
        http_indices = [m.start() for m in re.finditer(http_pattern, execution_log)]

        for idx in http_indices[-3:]:  # 取最近3个
            # 提取该工具调用的参数块（从 tool 开始到下一个 "tool" 或 "status" 之前）
            block_end = execution_log.find('"tool"', idx + 10)
            if block_end == -1:
                block_end = execution_log.find('"status"', idx)
            if block_end == -1:
                block_end = idx + 2000
            block = execution_log[idx:block_end]

            url = re.search(r'"url"\s*:\s*"([^"]+)"', block)
            method = re.search(r'"method"\s*:\s*"([^"]+)"', block)

            # body 可能包含转义引号，用非贪婪匹配到闭合引号
            body_match = re.search(r'"body"\s*:\s*"(.+?)(?<!\\)"(?:\s*[,}])', block, re.DOTALL)
            if not body_match:
                # 备选：匹配简单body
                body_match = re.search(r'"body"\s*:\s*"([^"]*)"', block)

            lines = []
            if method and url:
                lines.append(f"{method.group(1).upper()} {url.group(1)}")
            elif url:
                lines.append(f"GET {url.group(1)}")

            if body_match:
                body_val = body_match.group(1).replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace('\\\\', '\\')
                lines.append(f"Body:\n{body_val[:500]}")

            if lines:
                poc_blocks.append("\n".join(lines))

        # 提取 shell_exec / python_exec 的 payload
        exec_patterns = [
            (r'"tool"\s*:\s*"shell_exec".*?"command"\s*:\s*"([^"]+)"', "Shell Command"),
            (r'"tool"\s*:\s*"python_exec".*?"(?:script|code)"\s*:\s*"(.+?)(?:"\s*\}|"\s*,)', "Python Script"),
            (r'"tool"\s*:\s*"python_exec".*?"script"\s*:\s*"((?:[^"]|\\.)+)"', "Python Script"),
        ]

        for pattern, label in exec_patterns:
            matches = re.findall(pattern, execution_log, re.DOTALL)
            for match in matches[-2:]:
                clean = match.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"')
                poc_blocks.append(f"[{label}]\n{clean[:800]}")

        # 提取 SQL 注入 payload
        sql_pattern = r'(union\s+select|select\s+.*from|insert\s+into|update\s+.*set|delete\s+from|and\s+\d+=\d+|or\s+\d+=\d+|sleep\s*\(|benchmark\s*\()'
        sql_matches = re.findall(sql_pattern, execution_log, re.IGNORECASE)
        if sql_matches:
            # 提取包含 SQL payload 的整行
            for line in execution_log.split('\n'):
                for kw in ["union select", "' or '", "' and ", "sleep(", "benchmark("]:
                    if kw.lower() in line.lower() and len(line) > 10:
                        poc_blocks.append(f"[SQL Payload]\n{line.strip()[:500]}")
                        break
                if len(poc_blocks) > 8:
                    break

        # 去重
        seen = set()
        unique_blocks = []
        for block in poc_blocks:
            key = block[:50]
            if key not in seen:
                seen.add(key)
                unique_blocks.append(block)

        return "\n\n---\n\n".join(unique_blocks[:5]) if unique_blocks else ""

    def _extract_evidence(self, vuln_node: dict, execution_log: str) -> str:
        """提取验证证据：节点字段 > 执行日志关键结果 > 默认"""
        # 1. 从节点字段提取
        evidence = vuln_node.get("evidence", "")
        if evidence:
            return evidence

        # 2. 从执行日志提取关键验证结果
        if execution_log:
            return self._extract_evidence_from_execution_log(execution_log)

        return "验证证据未记录"

    def _extract_evidence_from_execution_log(self, execution_log: str) -> str:
        """从执行日志中提取关键的成功验证结果"""
        import re

        evidence_parts = []

        # 提取 HTTP 响应中的成功指示
        success_patterns = [
            r'(HTTP/\d\.\d\s+200\s+OK.*?)(?:\n{2,}|\Z)',
            r'(HTTP/\d\.\d\s+\d{3}.*?)(?:\n{2,}|\Z)',
            r'"status_code"\s*:\s*(\d+)',
            r'(验证成功|漏洞确认|存在漏洞|exploit successful|success)',
        ]

        for pattern in success_patterns[:2]:
            matches = re.findall(pattern, execution_log, re.IGNORECASE | re.DOTALL)
            for match in matches[:3]:
                clean = match.strip()
                if len(clean) > 10:
                    evidence_parts.append(f"HTTP Response:\n{clean[:600]}")

        # 提取关键返回数据（JSON/XML）
        json_pattern = r'(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})'
        json_matches = re.findall(json_pattern, execution_log)
        for match in json_matches:
            if any(kw in match for kw in ["success", "token", "password", "user", "admin", "flag"]):
                evidence_parts.append(f"Response Data:\n{match[:500]}")
                break

        # 提取关键发现
        key_findings = re.findall(r'(?:发现|找到|确认|成功)[：:]\s*(.+?)(?:\n|$)', execution_log)
        for finding in key_findings[:3]:
            evidence_parts.append(f"关键发现: {finding.strip()[:200]}")

        # 去重并拼接
        seen = set()
        unique_parts = []
        for part in evidence_parts:
            key = part[:40]
            if key not in seen:
                seen.add(key)
                unique_parts.append(part)

        result = "\n\n".join(unique_parts[:4])
        return result if result else execution_log[:500].strip()

    def _extract_target_url(self, execution_log: str) -> str:
        """从执行日志中提取目标URL"""
        import re
        url_pattern = r'(https?://[^\s"\'\)]+)'
        matches = re.findall(url_pattern, execution_log)
        if matches:
            return matches[0].rstrip('/')
        return ""

    def _build_reproduction_steps(self, vuln_node: dict, execution_log: str, affected_url: str) -> list:
        """构建复现步骤：节点字段 > 执行日志 > 默认"""
        # 1. 从节点字段提取
        steps = vuln_node.get("exploitation_conditions", [])
        if steps:
            return steps if isinstance(steps, list) else [steps]

        # 2. 从执行日志推断
        if execution_log:
            inferred = self._infer_steps_from_execution_log(execution_log, affected_url)
            if inferred:
                return inferred

        # 3. 默认步骤
        url = affected_url or "目标URL"
        return [
            f"1. 访问目标地址: {url}",
            "2. 构造并发送恶意请求",
            "3. 观察响应，验证漏洞存在",
        ]

    def _infer_steps_from_execution_log(self, execution_log: str, affected_url: str) -> list:
        """从执行日志中推断复现步骤"""
        import re
        steps = []

        # 提取 http_request 的步骤
        http_pattern = r'"tool"\s*:\s*"http_request".*?"params"\s*:\s*\{.*?\}'
        http_matches = re.findall(http_pattern, execution_log, re.DOTALL)
        for i, match in enumerate(http_matches[:4], 1):
            url = re.search(r'"url"\s*:\s*"([^"]+)"', match)
            method = re.search(r'"method"\s*:\s*"([^"]+)"', match)
            body = re.search(r'"body"\s*:\s*"([^"]+)"', match)

            parts = []
            if method and url:
                parts.append(f"发送 {method.group(1).upper()} 请求到 {url.group(1)}")
            elif url:
                parts.append(f"发送请求到 {url.group(1)}")
            if body:
                parts.append(f"，Payload: {body.group(1)[:100]}")

            if parts:
                steps.append(f"{i}. {''.join(parts)}")

        # 提取 python_exec 的步骤
        py_pattern = r'"tool"\s*:\s*"python_exec"'
        py_matches = re.findall(py_pattern, execution_log)
        for i, _ in enumerate(py_matches[:2], len(steps) + 1):
            steps.append(f"{i}. 执行 Python 漏洞利用脚本")

        # 提取 shell_exec 的步骤
        sh_matches = re.findall(r'"tool"\s*:\s*"shell_exec"', execution_log)
        for i, _ in enumerate(sh_matches[:2], len(steps) + 1):
            steps.append(f"{i}. 执行 Shell 命令进行测试")

        # 添加验证步骤
        if steps:
            steps.append(f"{len(steps) + 1}. 观察响应，确认漏洞可利用")

        return steps

    def _generate_remediation_advice(self, vuln_type: str) -> str:
        """根据漏洞类型生成有针对性的修复建议"""
        advice_map = {
            "sql_injection": "1. 所有数据库查询必须使用参数化查询（PreparedStatement）或 ORM 框架\n2. 对用户输入进行白名单校验，拒绝特殊字符\n3. 启用数据库查询日志审计，及时发现异常 SQL",
            "xss": "1. 对所有用户输入进行 HTML 实体编码（如 < 转义为 &lt;）\n2. 实施 CSP（内容安全策略）头限制脚本执行\n3. 使用现代框架的自动转义功能（如 React/Vue 的 {{ }} 插值）",
            "rce": "1. 严禁将用户输入传入 eval()、system()、exec() 等代码执行函数\n2. 使用白名单校验用户输入，仅允许预期字符\n3. 部署 WAF 规则拦截常见 RCE payload",
            "command_injection": "1. 使用参数化 API 代替字符串拼接命令（如 subprocess.run(['ls', '-l'])）\n2. 对用户输入实施严格的白名单过滤\n3. 以最小权限运行应用进程",
            "ssrf": "1. 限制服务器端可访问的 URL 范围，使用白名单\n2. 禁用不必要的 URL 协议（file://、dict://、gopher://）\n3. 对解析后的 IP 进行校验，禁止访问内网地址",
            "csrf": "1. 所有状态变更操作必须携带 CSRF Token 验证\n2. 检查请求头中的 Origin/Referer\n3. 对敏感操作增加二次确认（验证码、密码确认）",
            "lfi": "1. 禁用动态文件包含功能\n2. 使用白名单限制可包含的文件路径\n3. 对用户传入的文件名进行 basename() 处理",
            "rfi": "1. 关闭 allow_url_include 配置\n2. 禁用远程 URL 文件包含\n3. 使用白名单校验文件路径",
            "file_upload": "1. 严格校验文件 MIME 类型和后缀名（白名单）\n2. 重命名上传文件，禁止保留原始文件名\n3. 上传文件存储在非 Web 可访问目录，禁止执行权限",
            "auth_bypass": "1. 强化身份验证逻辑，所有接口必须校验登录状态\n2. 实施多因素认证（MFA）\n3. 对敏感接口增加操作权限校验（垂直/水平越权检查）",
            "insecure_deserialization": "1. 禁用不安全的反序列化操作\n2. 对序列化数据实施签名验证（HMAC）\n3. 使用 JSON 等安全格式替代二进制序列化",
            "shiro_deserialization": "1. 升级 Apache Shiro 到最新版本（>=1.7.1）\n2. 修改默认密钥，使用随机生成的强密钥\n3. 启用 rememberMe Cookie 加密并验证",
            "xxe": "1. 禁用 XML 外部实体解析（setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)）\n2. 使用 JSON 替代 XML 数据交换格式\n3. 升级 XML 解析库到最新版本",
            "directory_traversal": "1. 对用户传入的路径进行 normalize 和 realpath 处理\n2. 校验最终路径是否在允许的基目录内\n3. 拒绝包含 ../ 或 ..\\ 的路径",
            "info_leak": "1. 生产环境关闭调试模式，隐藏详细错误信息\n2. 删除或限制访问 .git、.svn、.env、备份文件\n3. 统一返回标准化错误页面，不暴露系统内部信息",
            "weak_password": "1. 强制实施密码复杂度策略（8位以上，含大小写+数字+特殊字符）\n2. 禁止使用常见弱口令，对接 Have I Been Pwned API\n3. 启用登录失败锁定和 MFA",
            "user_enumeration": "1. 登录接口返回统一错误提示（如 \"用户名或密码错误\"）\n2. 增加验证码或速率限制防止自动化枚举\n3. 注册/找回密码接口不暴露用户是否存在",
            "open_redirect": "1. 使用白名单限制跳转目标域名\n2. 使用内部映射表代替直接 URL 跳转\n3. 对跳转参数进行签名验证",
            "jwt_bypass": "1. 使用强签名算法（RS256 而非 HS256/None）\n2. 服务端严格校验签名、过期时间和签发者\n3. JWT 密钥定期轮换，禁止硬编码",
            "sensitive_data_exposure": "1. 对存储和传输中的敏感数据进行加密（AES-256）\n2. 实施数据脱敏，非必要不返回完整敏感字段\n3. 启用 HTTPS 并配置 HSTS",
            "path_traversal": "1. 使用标准库函数规范化路径（os.path.abspath）\n2. 校验最终路径是否位于授权目录内\n3. 拒绝包含路径穿越字符的请求",
            "default_credentials": "1. 系统首次安装后强制修改默认密码\n2. 建立默认凭据清单，部署时逐一检查\n3. 使用自动化工具扫描默认账号",
            "idac": "1. 对每个接口实施权限校验（RBAC/ABAC）\n2. 禁止仅依赖前端隐藏控制权限\n3. 水平越权校验：确保用户只能访问自己的资源",
        }
        return advice_map.get(vuln_type.lower(), "1. 对漏洞点进行代码审计，定位问题根因\n2. 实施输入验证和输出编码\n3. 参考 OWASP 对应漏洞类型的修复指南")

    def _generate_global_reflector_prompt(self, simplified_graph: Dict[str, Any]) -> str:
        """
        生成用于全局反思的提示词，以提炼可复用的STE经验。

        该方法分析简化的因果图，生成针对全局反思的提示词，用于：
        - 识别成功的攻击模式和策略
        - 提取可复用的战术知识
        - 分析失败原因和改进建议
        - 生成策略-战术-示例(STE)知识框架

        Args:
            simplified_graph: 简化的因果图字典，包含节点和边信息

        Returns:
            全局反思提示词字符串，包含STE经验提取指导
        """
        simplified_graph_json = json.dumps(simplified_graph, indent=2, ensure_ascii=False)

        return f"""# 角色：首席渗透测试战略家与知识工程师

## 核心目标：
从一个已完成的、成功的攻击任务中，提炼出一个结构化的、可复用的经验，格式为“战略-战术-案例”(STE)。

## 待分析的成功攻击案例 (简化轨迹)：

```json
{simplified_graph_json}
```

## 提炼指令：

你必须严格按照以下步骤，将上述成功案例提炼成一个STE经验对象：

### 1. 评估成功质量 (CRITICAL)
你必须首先检查 `simplified_graph_json` 中是否存在 `node_type` 为 `ConfirmedVulnerability` 的节点。
- **如果存在 `ConfirmedVulnerability`**：这代表了一次高质量的、已验证的成功攻击。你的分析**必须**围绕导致这个节点的攻击路径展开。在 `global_summary` 中明确指出这是一个已确认的漏洞。
- **如果不存在 `ConfirmedVulnerability`**：这可能是一次偶然的成功（例如，仅找到flag但未理解漏洞），或者是一次常规的信息收集。你的分析应侧重于其机会主义性质和潜在的改进空间。

### 2. 提炼战略原则 (Strategic Principle)
- 这是最高层次的、一句话的攻击原则。
- 它应该回答“为什么（Why）”可以这么做，揭示了哪一类根本性的安全弱点。
- **示例**：“当认证令牌使用无MAC的CBC模式加密时，可通过篡改IV或前置密文块来伪造身份。”

### 3. 提炼战术手册 (Tactical Playbook)
- 这是实现该战略的、有序的、抽象的步骤列表。
- 它应该回答“如何做（How）”的步骤。
- 每个步骤都应该是一个动词短语，描述一个战术目标，而不是具体的工具调用。
- **示例**：
  ```json
  [
    "信息收集：获取原始加密令牌",
    "结构分析：识别加密模式、块大小和明文格式",
    "载荷构造：计算并生成篡改后的加密令牌",
    "攻击执行：使用篡改后的令牌访问受保护资源"
  ]
  ```

### 4. 定义适用场景 (Applicability)
- 这是一个标签列表，定义了该STE经验最可能在哪些场景下被复用。
- **示例**：`["web_security", "session_hijacking", "cbc_bit_flipping", "ctf"]`

## 输出格式 (仅限JSON):

你**必须**输出一个结构合法的 JSON 对象，其中必须包含 `global_summary`, `strategic_analysis`, 和 `global_insight` 键。`global_insight` 必须严格遵循STE格式。

{{
  "global_summary": "用一句话总结整个任务的核心战役路径和最终结果。",
  "strategic_analysis": "对整体战略的详细分析，包括规划、执行和反思的亮点与不足。",
  "global_insight": {{
    "strategic_principle": "此处填写你提炼的战略原则。",
    "tactical_playbook": [
      "此处填写第一个战术步骤",
      "此处填写第二个战术步骤",
      "..."
    ],
    "applicability": ["tag1", "tag2", "..."]
  }}
}}
"""

    async def reflect_global(self, graph_manager: GraphManager) -> Dict:
        """
        执行全局反思，生成最高层次的战略洞见和经验总结。

        该函数实现了对整个任务图谱的全局反思功能，包括：
        - 检查任务目标是否达成
        - 简化因果图并生成全局反思提示词
        - 调用LLM生成战略分析和全局洞察
        - 提取可复用的STE（策略-战术-示例）经验

        Args:
            graph_manager: 图管理器实例，提供任务图谱和状态信息

        Returns:
            全局反思结果字典，包含战略分析、全局洞察、指标等
        """
        if not graph_manager.is_goal_achieved():
            return {
                "global_summary": "任务未成功，跳过全局经验归档。",
                "strategic_analysis": "",
                "global_insight": None,
                "metrics": None,
            }

        simplified_graph = graph_manager.get_simplified_graph()
        prompt = self._generate_global_reflector_prompt(simplified_graph)
        messages = [{"role": "user", "content": prompt}]

        try:
            response, call_metrics = await self.llm_client.send_message(messages, role="reflector")
            if not response:
                raise ValueError("LLM returned no data for global reflection.")

            # response is already a dictionary from llm_client, not a JSON string
            global_reflection_data = response
            global_reflection_data["metrics"] = call_metrics

            if global_reflection_data.get("global_insight"):
                global_reflection_data["global_insight"]["example_trajectory"] = simplified_graph

            # 新增：全局反思阶段推送钉钉 + 触发停止
            await self._notify_dingtalk_from_graph(graph_manager)

            return global_reflection_data

        except (json.JSONDecodeError, ValueError) as e:
            print(f"解析Global Reflector输出失败: {e}")
            return {
                "global_summary": "全局反思失败，无法解析LLM输出。",
                "strategic_analysis": "",
                "global_insight": None,
                "metrics": None,
            }

    # 触发推送和停止的最低严重程度阈值
    _MIN_SEVERITY_RANK = {"信息": 0, "低危": 1, "中危": 2, "高危": 3, "严重": 4}
    _MIN_SEVERITY_FOR_NOTIFICATION = "中危"  # 只有中危及以上才推送和停止

    async def _notify_dingtalk_from_graph(self, graph_manager: GraphManager) -> None:
        """
        从因果图中提取已确认漏洞，推送钉钉通知并创建停止信号。

        严重程度阈值: 只有 中危 及以上才会触发推送和停止。
        在 reflect() 子任务反思 和 reflect_global() 全局反思 中都会调用。
        """
        try:
            from core.dingtalk_notifier import DingTalkNotifier
            from conf.config import (
                DINGTALK_ENABLED, DINGTALK_WEBHOOK, DINGTALK_SECRET,
                DINGTALK_STOP_ON_VULN
            )

            if not (DINGTALK_ENABLED and DINGTALK_WEBHOOK and DINGTALK_SECRET):
                return

            # 从因果图中提取所有 ConfirmedVulnerability 节点
            confirmed_vulns = []
            if graph_manager and hasattr(graph_manager, 'causal_graph'):
                for node_id, data in graph_manager.causal_graph.nodes(data=True):
                    node_type = data.get("node_type", "")
                    if node_type in ("ConfirmedVulnerability", "Vulnerability"):
                        node_data = dict(data)
                        node_data["id"] = node_id
                        confirmed_vulns.append(node_data)

            if not confirmed_vulns:
                return

            # 过滤：只处理 severity >= 中危 的漏洞
            min_rank = self._MIN_SEVERITY_RANK.get(self._MIN_SEVERITY_FOR_NOTIFICATION, 2)
            notify_vulns = []
            for vuln_node in confirmed_vulns:
                vuln_info = self._extract_vulnerability_info(vuln_node, "")
                severity_rank = self._MIN_SEVERITY_RANK.get(vuln_info.get("severity", "信息"), 0)
                if severity_rank >= min_rank:
                    notify_vulns.append((vuln_node, vuln_info))

            if not notify_vulns:
                _get_console().print(
                    f"[DingTalk] 发现 {len(confirmed_vulns)} 个漏洞，"
                    f"但严重程度均低于 {self._MIN_SEVERITY_FOR_NOTIFICATION}，不触发推送",
                    style="yellow"
                )
                return

            notifier = DingTalkNotifier(
                webhook_url=DINGTALK_WEBHOOK,
                secret=DINGTALK_SECRET
            )

            for vuln_node, vuln_info in notify_vulns:
                # 避免重复推送
                if vuln_node.get("_dingtalk_notified"):
                    continue

                success = await notifier.send_vulnerability_alert(vuln_info)
                if success:
                    _get_console().print(
                        f"[DingTalk] 漏洞推送成功 [{vuln_info.get('severity', '?')}]: "
                        f"{vuln_info.get('title', 'Unknown')}",
                        style="bold green"
                    )
                    # 标记已推送
                    if graph_manager and hasattr(graph_manager, 'causal_graph'):
                        if vuln_node["id"] in graph_manager.causal_graph.nodes:
                            graph_manager.causal_graph.nodes[vuln_node["id"]]["_dingtalk_notified"] = True
                else:
                    _get_console().print(
                        "[DingTalk] 漏洞推送失败",
                        style="bold red"
                    )

                # 创建停止信号（仅中危及以上）
                if DINGTALK_STOP_ON_VULN and graph_manager and hasattr(graph_manager, 'task_id'):
                    import os, json, tempfile
                    halt_file = os.path.join(tempfile.gettempdir(), f"{graph_manager.task_id}.halt")
                    halt_payload = {
                        "reason": "vulnerability_confirmed",
                        "vulnerability": vuln_info,
                        "timestamp": time.time()
                    }
                    with open(halt_file, "w", encoding="utf-8") as f:
                        json.dump(halt_payload, f, ensure_ascii=False)
                    _get_console().print(
                        f"[DingTalk] 已发现 {vuln_info.get('severity', '?')} 级别漏洞，"
                        f"测试任务已自动停止: {vuln_info.get('title', '')}",
                        style="bold yellow"
                    )

        except Exception as e:
            _get_console().print(f"[DingTalk] 推送过程出错: {e}", style="yellow")
