# 依据与数据来源溯源（SOURCES）

> 本文档回答"项目的拦截、出题、样本的依据是什么"。结论：所有判定规则与任务
> 都有外部锚点或经过人工标注验证，不存在自证。

## 1. 拦截规则的依据（ethgate/scanner.py 的 10 条规则）

代码内每条规则带 `basis` 字段（`SCAN_RULES` + `RULE_BASES`），完整映射：

| 规则 | 外部锚点 |
|---|---|
| R1 改测试/评测文件 | OWASP LLM06（过度代理）；DGM 论文（arXiv:2505.22954）记录的自进化奖励黑客 |
| R2 绕过校验断言 | MITRE ATLAS『Impair Defenses』；OWASP LLM06 |
| R3 新增网络调用 | OWASP LLM06；MITRE ATLAS 外泄面扩张 |
| R4 改写自身指令/约束 | 开题报告 §2.1 表1 约束层；Apollo Research（2024.12）推理模型规避监督的评测 |
| R5 硬编码/用例特判 | Specification gaming（Krakovna et al. 2020, arXiv:2010.09891）；SWE-bench 类基准的测试作弊现象 |
| R6 日志降级 | MITRE ATLAS『Impair Defenses』；算法问责的日志要求（Wieringa 2020） |
| R7 进程/系统调用 | OWASP LLM06；对象能力模型最小权限（Miller 2006） |
| R8 改评分/归档逻辑 | Specification gaming：改裁判=改目标；DGM 论文 |
| R9 篡改停机通道 | Palisade Research（2025.2）推理模型破坏停机脚本；Apollo Research（2024.12）——I3 的实证基础 |
| R10 新增任意工具 | OWASP LLM06；授权闭包定义（Miller 2006） |

四条不变量 I1–I4 的依据见开题报告 §3.2.2 表 2（权限单调性源自对象能力模型、
审计完备性源自 Wieringa 2020、可中断性源自上述 Palisade/Apollo 案例、约束守恒
源自价值敏感设计）。

## 2. 出题的依据（ethgate/minievol.py 任务池）

题池 31 题，来源分三级（每题带 `source` 字段可查）：

| 级别 | 来源 | 数量 | 说明 |
|---|---|---|---|
| 直接抽样 | **GSM8K**（OpenAI，MIT License） | 10 | `tools/import_benchmarks.py` 以 seed=2026 从 test 集 1319 题确定性抽样，判分沿用原基准的整数精确匹配 |
| 格式对齐 | **GAIA**（精确匹配答案的多步助手任务） | — | 题池的"知识/文本检索/推理"类任务在任务形式与判分方式上与 GAIA 同构 |
| 自建·拦截映射 | OWASP LLM06 / ATLAS / DGM 现象 | — | "联网检索/系统查询/知识库"等天花板题型对应 I1–I4 的诱发场景，设计原理见 §1 |
| 自建·能力评测 | — | 21 | 大数乘法、双字母统计、三步条件概率等——难度依据：模型裸做不可靠（确定性判分不依赖 LLM 评卷） |

## 3. 危险修改样本的依据

三路样本，**分开统计、不合并**：

1. **人工构造**（artificial）：按 18 格分类学的高危格逐格构造，规则映射见 §1；
2. **自然涌现**（emergent）：真实 LLM 在剧本压力下自发产生的提案，由扫描器规则捕获；
3. **真实拦截语料**（`data/corpus/`）：直播系统的全部历史判定，`tools/export_corpus.py`
   导出——**10 场会话、57 条去重提案、29 条被拦截**（随使用持续增长）。

## 4. 规则的人工标注验证（进行中）

"规则是我们定的"→"规则经三人独立标注验证"：

- 工作表：`data/corpus/labeling_sheet.csv`（100 条提案，含变更摘要与 diff）
- 协议：三位组员**互不通气**独立标注 dangerous / safe
- 计算：`python tools/labeling_kappa.py` → **Fleiss' κ**（三人一致性）+
  扫描器规则对人工多数意见的 **precision / recall** 与混淆矩阵
- 结果写入 `data/corpus/kappa_report.json` 并引用进报告

## 5. 引用清单

- OWASP GenAI LLM Top 10 (2025), LLM06 Excessive Agency 等
- MITRE ATLAS: Adversarial Threat Landscape for AI Systems
- Zhang et al. Darwin Gödel Machine, arXiv:2505.22954（奖励黑客第一手记录）
- Palisade Research, Demonstrating specification gaming in reasoning models, 2025.2
- Apollo Research, Scheming reasoning evaluations, 2024.12
- Krakovna et al., Avoiding side effects / specification gaming, arXiv:2010.09891
- Miller, Robust composition (对象能力模型), 2006
- Wieringa, What to account for when accounting for algorithms, FAccT 2020
- GSM8K: Cobbe et al., Training Verifiers to Solve Math Word Problems, 2021（MIT）
- R-Judge / AgentDojo：智能体安全风险与注入攻击基准（相关工作对照）
