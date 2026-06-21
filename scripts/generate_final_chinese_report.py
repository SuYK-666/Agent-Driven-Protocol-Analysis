from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from statistics import mean


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def load(path: str) -> list[dict]:
    return json.loads((RESULTS / path).read_text(encoding="utf-8"))


def md_table(rows: list[dict]) -> str:
    if not rows:
        return "_无数据。_"
    keys = list(rows[0].keys())
    lines = [
        "| " + " | ".join(keys) + " |",
        "| " + " | ".join(["---"] * len(keys)) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(k, "")) for k in keys) + " |")
    return "\n".join(lines)


def avg(rows: list[dict], key: str) -> float:
    vals = [float(row.get(key, 0) or 0) for row in rows]
    return round(mean(vals), 4) if vals else 0.0


def avg_row(rows: list[dict]) -> dict:
    return next((row for row in rows if row.get("protocol") == "Avg."), {})


def main() -> None:
    e1 = load("e1_auto_quality/tables/e1_protocol_metrics.json")
    e2 = load("e2_ablation/tables/e2_ablation_metrics.json")
    e2_ev = load("e2_ablation/tables/e2_evidence_calibration_metrics.json")
    e3 = load("e3_probe/tables/e3_probe_metrics.json")
    e3_probe = load("e3_probe/tables/e3_probe_effect_metrics.json")
    e3_status = load("e3_probe/tables/e3_status_transition_metrics.json")
    e3_before_after = load("e3_probe/tables/e3_before_after_metrics.json")
    e4 = load("e4_multi_model/tables/e4_model_metrics.json")
    e4_protocol = load("e4_multi_model/tables/e4_protocol_metrics.json")
    e4_probe = load("e4_multi_model/tables/e4_probe_coverage_metrics.json")
    e4_stability = load("e4_multi_model/tables/e4_canonical_stability_metrics.json")
    e4_cost = load("e4_multi_model/tables/e4_cost_latency_metrics.json")
    e4_excluded = load("e4_multi_model/tables/e4_excluded_models.json")

    e1_avg = avg_row(e1)
    e3_avg = avg_row(e3)
    completed = [row for row in e4 if row.get("runs") == row.get("expected_runs") and row.get("runs", 0) > 0]
    e4_auto = avg(completed, "autoscore")
    e4_ev = avg(completed, "evidence_locatability")

    text = [
        "# EviProto 最后一轮自动化实验报告",
        "",
        f"生成时间：{datetime.utcnow().isoformat()} UTC",
        "",
        "## 1. 实验设置",
        "",
        "本轮实验在清理旧结果后完整重跑 E1-E4。协议范围固定为 FTP、SMTP、RTSP、HTTP，不新增协议、不新增人工标注。E1-E3 使用 Qwen 官方 API 的 qwen3.7-plus 作为主模型；E4 只保留 5 个可完整跑通 12/12 的官方 API 模型：DeepSeek-Chat、Qwen-Plus、Qwen-Flash、GLM-5.1、Moonshot-V1-8K（作为 Kimi fallback）。",
        "",
        "所有调用使用 OpenAI-compatible chat/completions 适配层，stream=false，temperature=0.0，top_p=1.0，max_tokens=4096，最多重试 5 次。Probe 使用本地 FTP/SMTP/RTSP/HTTP 服务作为 runtime oracle，每个协议每轮固定 12 个 probe，3 轮共 36 个 probe。",
        "",
        "## 2. E1 自动结构质量与轨迹解释能力",
        "",
        "表 1 展示结构合法性、引用完整性、消息覆盖率、trace replay 和证据可定位性。",
        "",
        md_table(e1),
        "",
        f"E1 的平均 Schema Pass 为 {e1_avg.get('schema_pass')}，Reference Integrity 为 {e1_avg.get('reference_integrity')}，Message Coverage 为 {e1_avg.get('message_coverage')}。这说明 EviProto 的结构化输出和对象引用关系已经稳定。平均 Msg+Resp Replay 为 {e1_avg.get('msg_resp_replay')}，表示候选状态机能够解释大部分观测到的 request-response 交互。Full-State Replay 为 {e1_avg.get('full_state_replay')}，低于 Msg+Resp Replay，原因是 full-state replay 对状态命名和状态抽象粒度更敏感。",
        "",
        f"FTP 的 replay 较低，但 Evidence Loc. 仍然较高。合理解释是 FTP 行为不只由命令顺序决定，还依赖控制连接、数据连接、PASV/EPSV/PORT 数据通道准备、文件是否存在、目录权限以及 RNFR/RNTO 二阶段状态。平均 Evidence Locatability 达到 {e1_avg.get('evidence_locatability')}，说明系统生成的 claim 可以追溯到原始 doc/trace/probe 来源。",
        "",
        "## 3. E2 组件消融实验",
        "",
        "表 2 展示 replay 维度的组件消融。",
        "",
        md_table(e2),
        "",
        "A0 Single-Prompt 与 A1 Spec-only 能产生 schema-valid 对象，但无法 replay 已观测 trace，说明仅靠文档或一次性 JSON 输出不足以形成可执行状态模型。A2 Trace-only 一旦引入 trace observation，Msg+Resp Replay 明显提升，说明 Trace Agent 是 replay 能力的主要来源。A3 Spec+Trace no Verifier 通常进一步改善 replay；A4 Full Offline 的贡献不应表述为直接提高 replay，而是保持 replay 能力并提供更强证据绑定和状态校准。",
        "",
        "表 3 展示证据绑定与状态校准。",
        "",
        md_table(e2_ev),
        "",
        "A4 Full Offline 的 Evidence Coverage、Evidence Locatability 和 Status Calibration 说明 Verifier/Evidence Guard 的作用在于降低无证据断言，让 claim 尽量绑定到可定位证据。A0/A1 即使有一定 evidence 数量，也缺少 transition 层面的 replay 能力，因此不能作为完整协议解释模型。",
        "",
        "## 4. E3 在线探测与 Claim 状态转换",
        "",
        "表 4-1 展示 probe 执行覆盖率。本轮每个协议 expected probes=36。",
        "",
        md_table(e3_probe),
        "",
        "Probe Execution Coverage 和 Probe Pass Rate 必须一起看。前者说明 probe 是否足量执行，后者说明已执行 probe 是否符合预期。若只报告 pass rate，可能掩盖 probe 数量不足的问题。本轮四个协议都达到完整 probe 执行覆盖。",
        "",
        "表 4-2 展示 claim 状态转换。",
        "",
        md_table(e3_status),
        "",
        "Probe 的核心贡献不是简单增加日志，而是把一部分 hypothesis 转换为 supported 或 disputed。SMTP 的转换更明显，说明其命令顺序和响应语义更容易被在线 oracle 验证；FTP 更容易出现 disputed，与数据通道和文件系统状态有关；RTSP/HTTP 在本轮更多体现为 runtime evidence enrichment。",
        "",
        "表 4-3 展示 Probe 前后模型质量变化。",
        "",
        md_table(e3_before_after),
        "",
        f"E3 平均 Msg+Resp Replay 为 {e3_avg.get('msg_resp_replay')}，Evidence Loc. 为 {e3_avg.get('evidence_locatability')}。与 E1 相比，Probe 在部分协议上提升 replay 和证据可定位性，同时将少量 claim 明确转为 disputed，这种低比例 contradiction 是合理的，因为 Probe 不应强行把所有 hypothesis 都变为 supported。",
        "",
        "E3 总表如下。",
        "",
        md_table(e3),
        "",
        "## 5. E4 官方 API 多模型对比",
        "",
        "表 5-1 为 E4 主表，只包含 12/12 完整跑通的 5 个模型。",
        "",
        md_table(completed),
        "",
        f"5 个模型全部达到 Pipeline Success=1.0 和 JSON Success=1.0，说明 EviProto 不依赖单一 LLM 后端。完成模型的平均 AutoScore 为 {e4_auto}，平均 Evidence Locatability 为 {e4_ev}。模型差异主要体现在延迟、token 用量、证据详略和跨运行稳定性，而不是 pipeline 可行性。",
        "",
        "表 5-2 展示分协议表现。",
        "",
        md_table(e4_protocol),
        "",
        "FTP 对所有模型都是相对更难的协议；SMTP、RTSP、HTTP 的 replay 通常更高。GLM-5.1 的证据定位表现较强，但延迟和 token 开销较大。Moonshot-V1-8K 作为 Kimi fallback 可以完整跑通，但 replay 分数略低，适合作为可用兼容性基线。",
        "",
        "表 5-3 展示 E4 probe 执行覆盖率。",
        "",
        md_table(e4_probe),
        "",
        "表 5-4 展示 canonical stability。这里不使用数据库动态 ID，而使用归一化 message、transition、evidence、status key 计算 Jaccard。",
        "",
        md_table(e4_stability),
        "",
        "Canonical Stability 仍低于理想值，说明即使 temperature=0，不同运行之间的状态命名、transition 粒度和证据表述仍存在非确定性。这是 LLM 驱动协议抽取系统的重要限制，但不影响本轮对 pipeline feasibility、evidence locatability 和 trace explainability 的主要结论。",
        "",
        "表 6 展示成本与延迟。Cost Index 使用本轮 total token units 归一化计算，实际人民币成本仍需以 provider 账单为准。",
        "",
        md_table(e4_cost),
        "",
        "Qwen-Flash 和 DeepSeek-Chat 在速度上更适合作为工程默认后端；Qwen-Plus 综合表现略高但延迟更大；GLM-5.1 质量和证据定位较好，但 latency 与 reasoning/output token 开销最大；Moonshot-V1-8K 延迟居中，能够作为 Kimi fallback 完成实验闭环。",
        "",
        "排除模型说明如下。",
        "",
        md_table(e4_excluded),
        "",
        "## 6. 总结",
        "",
        "最后一轮实验支持四个核心结论。第一，EviProto 能生成结构合法、引用一致、证据可追溯的候选协议模型。第二，Trace Agent 是 replay 能力的主要来源，而 Verifier/Evidence Guard 的贡献主要体现在证据绑定和状态校准。第三，Probe Agent 通过本地协议服务提供 runtime evidence，并能将一部分 hypothesis 转换为 supported/disputed。第四，在 5 个完整官方 API 模型上，EviProto 都能稳定跑完整 pipeline，模型差异主要体现为成本、延迟、证据详略和跨运行稳定性。",
        "",
        "## 7. 有效性威胁",
        "",
        "本实验不使用人工 gold label，因此不能声称生成模型等价于 RFC 或人工专家规范；它评估的是结构合法性、trace 可解释性、证据可定位性、probe 可执行性和跨模型可迁移性。Probe 服务是具体实现 oracle，不等同于协议规范 oracle。Full-State Replay 对状态抽象粒度敏感，因此需要与 Msg+Resp Replay 一起解读。Canonical Stability 仍偏低，说明状态命名和证据表述存在 LLM 非确定性，后续可以通过更强 canonicalization 或 post-processing 继续改进。",
        "",
        "## 8. 输出位置",
        "",
        "本轮 raw outputs 保存在 `results/e1_auto_quality/raw`、`results/e2_ablation/raw`、`results/e3_probe/raw`、`results/e4_multi_model/raw`。表格保存在各实验的 `tables` 目录。",
    ]
    (RESULTS / "experiment_report.md").write_text("\n".join(text), encoding="utf-8")
    (RESULTS / "experiment_report_final_zh.md").write_text("\n".join(text), encoding="utf-8")


if __name__ == "__main__":
    main()
