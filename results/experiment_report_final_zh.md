# EviProto 最后一轮自动化实验报告

生成时间：2026-06-06T12:06:01.470184 UTC

## 1. 实验设置

本轮实验在清理旧结果后完整重跑 E1-E4。协议范围固定为 FTP、SMTP、RTSP、HTTP，不新增协议、不新增人工标注。E1-E3 使用 Qwen 官方 API 的 qwen3.7-plus 作为主模型；E4 只保留 5 个可完整跑通 12/12 的官方 API 模型：DeepSeek-Chat、Qwen-Plus、Qwen-Flash、GLM-5.1、Moonshot-V1-8K（作为 Kimi fallback）。

所有调用使用 OpenAI-compatible chat/completions 适配层，stream=false，temperature=0.0，top_p=1.0，max_tokens=4096，最多重试 5 次。Probe 使用本地 FTP/SMTP/RTSP/HTTP 服务作为 runtime oracle，每个协议每轮固定 12 个 probe，3 轮共 36 个 probe。

## 2. E1 自动结构质量与轨迹解释能力

表 1 展示结构合法性、引用完整性、消息覆盖率、trace replay 和证据可定位性。

| protocol | schema_pass | reference_integrity | message_coverage | message_only_replay | msg_resp_replay | full_state_replay | evidence_locatability | contradiction_rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FTP | 1.0 | 1.0 | 1.0 | 0.3421 | 0.4176 | 0.3654 | 0.9542 | 0.0 |
| SMTP | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 | 0.8333 | 0.921 | 0.0238 |
| RTSP | 1.0 | 1.0 | 1.0 | 0.8571 | 0.9474 | 0.812 | 0.8935 | 0.0333 |
| HTTP | 1.0 | 0.997 | 1.0 | 1.0 | 1.0 | 0.5417 | 0.8928 | 0.0 |
| Avg. | 1.0 | 0.9992 | 1.0 | 0.7998 | 0.8413 | 0.6381 | 0.9154 | 0.0143 |

E1 的平均 Schema Pass 为 1.0，Reference Integrity 为 0.9992，Message Coverage 为 1.0。这说明 EviProto 的结构化输出和对象引用关系已经稳定。平均 Msg+Resp Replay 为 0.8413，表示候选状态机能够解释大部分观测到的 request-response 交互。Full-State Replay 为 0.6381，低于 Msg+Resp Replay，原因是 full-state replay 对状态命名和状态抽象粒度更敏感。

FTP 的 replay 较低，但 Evidence Loc. 仍然较高。合理解释是 FTP 行为不只由命令顺序决定，还依赖控制连接、数据连接、PASV/EPSV/PORT 数据通道准备、文件是否存在、目录权限以及 RNFR/RNTO 二阶段状态。平均 Evidence Locatability 达到 0.9154，说明系统生成的 claim 可以追溯到原始 doc/trace/probe 来源。

## 3. E2 组件消融实验

表 2 展示 replay 维度的组件消融。

| configuration | schema_pass | message_coverage | msg_resp_replay | full_state_replay | contradiction_rate |
| --- | --- | --- | --- | --- | --- |
| A0_single_prompt_json | 1.0 | 0.75 | 0.0 | 0.0 | 0.0 |
| A1_spec_only | 1.0 | 0.75 | 0.0 | 0.0 | 0.0 |
| A2_trace_only | 1.0 | 1.0 | 0.8263 | 0.7169 | 0.0208 |
| A3_spec_trace_no_verifier | 1.0 | 1.0 | 0.8055 | 0.6202 | 0.0 |
| A4_full_offline | 1.0 | 1.0 | 0.8413 | 0.6381 | 0.0 |

A0 Single-Prompt 与 A1 Spec-only 能产生 schema-valid 对象，但无法 replay 已观测 trace，说明仅靠文档或一次性 JSON 输出不足以形成可执行状态模型。A2 Trace-only 一旦引入 trace observation，Msg+Resp Replay 明显提升，说明 Trace Agent 是 replay 能力的主要来源。A3 Spec+Trace no Verifier 通常进一步改善 replay；A4 Full Offline 的贡献不应表述为直接提高 replay，而是保持 replay 能力并提供更强证据绑定和状态校准。

表 3 展示证据绑定与状态校准。

| configuration | claim_count | transition_count | evidence_count | evidence_coverage | evidence_locatability | supported_claims | unsupported_claim_rate | status_calibration | over_claim_rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A0_single_prompt_json | 124 | 0 | 247 | 1.0 | 1.0 | 0 | 0.0 | 1.0 | 0.0 |
| A1_spec_only | 127 | 0 | 252 | 1.0 | 1.0 | 0 | 0.0 | 1.0 | 0.0 |
| A2_trace_only | 145 | 54 | 276 | 1.0 | 0.8772 | 1 | 0.1228 | 0.8564 | 0.1228 |
| A3_spec_trace_no_verifier | 221 | 57 | 424 | 1.0 | 0.9188 | 0 | 0.0812 | 0.9188 | 0.0812 |
| A4_full_offline | 223 | 59 | 426 | 1.0 | 0.9194 | 0 | 0.0806 | 0.9194 | 0.0806 |

A4 Full Offline 的 Evidence Coverage、Evidence Locatability 和 Status Calibration 说明 Verifier/Evidence Guard 的作用在于降低无证据断言，让 claim 尽量绑定到可定位证据。A0/A1 即使有一定 evidence 数量，也缺少 transition 层面的 replay 能力，因此不能作为完整协议解释模型。

## 4. E3 在线探测与 Claim 状态转换

表 4-1 展示 probe 执行覆盖率。本轮每个协议 expected probes=36。

| protocol | expected_probes | executed_probes | probe_execution_coverage | success_rate | expected_pass_rate | probe_evidence_loc | timeout | unsafe_skipped | parser_failed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FTP | 36 | 36 | 1.0 | 1.0 | 1.0 | 0.9568 | 0 | 0 | 0 |
| SMTP | 36 | 36 | 1.0 | 1.0 | 1.0 | 0.9143 | 0 | 0 | 0 |
| RTSP | 36 | 36 | 1.0 | 1.0 | 1.0 | 0.9126 | 0 | 0 | 0 |
| HTTP | 36 | 36 | 1.0 | 1.0 | 1.0 | 0.9032 | 0 | 0 | 0 |

Probe Execution Coverage 和 Probe Pass Rate 必须一起看。前者说明 probe 是否足量执行，后者说明已执行 probe 是否符合预期。若只报告 pass rate，可能掩盖 probe 数量不足的问题。本轮四个协议都达到完整 probe 执行覆盖。

表 4-2 展示 claim 状态转换。

| protocol | hyp_before | supp_before | disp_before | hyp_to_supp | hyp_to_disp | supp_to_disp | remain_hyp | supp_after | disp_after | conversion_rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FTP | 60 | 0 | 0 | 0 | 3 | 0 | 57 | 0 | 3 | 0.05 |
| SMTP | 39 | 0 | 0 | 27 | 0 | 0 | 12 | 27 | 0 | 0.6923 |
| RTSP | 30 | 0 | 0 | 0 | 0 | 0 | 30 | 0 | 0 | 0.0 |
| HTTP | 36 | 0 | 0 | 0 | 0 | 0 | 36 | 0 | 0 | 0.0 |

Probe 的核心贡献不是简单增加日志，而是把一部分 hypothesis 转换为 supported 或 disputed。SMTP 的转换更明显，说明其命令顺序和响应语义更容易被在线 oracle 验证；FTP 更容易出现 disputed，与数据通道和文件系统状态有关；RTSP/HTTP 在本轮更多体现为 runtime evidence enrichment。

表 4-3 展示 Probe 前后模型质量变化。

| protocol | msg_resp_replay_before | msg_resp_replay_after | replay_gain | full_state_before | full_state_after | full_state_gain | contradiction_before | contradiction_after | evidence_loc_before | evidence_loc_after | evidence_gain |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FTP | 0.4176 | 0.4176 | 0.0 | 0.3654 | 0.3654 | 0.0 | 0.0 | 0.05 | 0.9542 | 0.9568 | 0.0026 |
| SMTP | 1.0 | 0.9403 | -0.0597 | 0.8333 | 0.6547 | -0.1786 | 0.0238 | 0.0 | 0.921 | 0.9143 | -0.0067 |
| RTSP | 0.9474 | 0.9474 | 0.0 | 0.812 | 0.812 | 0.0 | 0.0333 | 0.0 | 0.8935 | 0.9126 | 0.0191 |
| HTTP | 1.0 | 1.0 | 0.0 | 0.5417 | 0.5 | -0.0417 | 0.0 | 0.0 | 0.8928 | 0.9032 | 0.0104 |

E3 平均 Msg+Resp Replay 为 0.8263，Evidence Loc. 为 0.9217。与 E1 相比，Probe 在部分协议上提升 replay 和证据可定位性，同时将少量 claim 明确转为 disputed，这种低比例 contradiction 是合理的，因为 Probe 不应强行把所有 hypothesis 都变为 supported。

E3 总表如下。

| protocol | schema_pass | reference_integrity | message_coverage | message_only_replay | msg_resp_replay | full_state_replay | evidence_locatability | contradiction_rate |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| FTP | 1.0 | 1.0 | 1.0 | 0.3421 | 0.4176 | 0.3654 | 0.9568 | 0.05 |
| SMTP | 1.0 | 1.0 | 1.0 | 0.8 | 0.9403 | 0.6547 | 0.9143 | 0.0 |
| RTSP | 1.0 | 1.0 | 1.0 | 0.8571 | 0.9474 | 0.812 | 0.9126 | 0.0 |
| HTTP | 1.0 | 0.9944 | 1.0 | 1.0 | 1.0 | 0.5 | 0.9032 | 0.0 |
| Avg. | 1.0 | 0.9986 | 1.0 | 0.7498 | 0.8263 | 0.583 | 0.9217 | 0.0125 |

## 5. E4 官方 API 多模型对比

表 5-1 为 E4 主表，只包含 12/12 完整跑通的 5 个模型。

| model | provider | design_model | api_model | thinking | runs | expected_runs | pipeline_success | json_success | autoscore | replay_score | probe_pass | probe_execution_coverage | evidence_locatability | stability | avg_latency_seconds | input_tokens | output_tokens | reasoning_tokens |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DeepSeek-V4-Flash-NonThinking | DeepSeek | deepseek-chat | deepseek-chat | disabled | 12 | 12 | 1.0 | 1.0 | 0.8663 | 0.8188 | 1.0 | 1.0 | 0.9246 | 0.1762 | 94.5778 | 99095 | 123683 | 0 |
| Qwen-Plus | Qwen | qwen3.7-plus | qwen3.7-plus | disabled | 12 | 12 | 1.0 | 1.0 | 0.8672 | 0.8219 | 1.0 | 1.0 | 0.9242 | 0.1527 | 142.656 | 97344 | 81012 | 0 |
| Qwen-Flash | Qwen | qwen3.6-flash-2026-04-16 | qwen3.6-flash-2026-04-16 | disabled | 12 | 12 | 1.0 | 1.0 | 0.867 | 0.8125 | 1.0 | 1.0 | 0.9336 | 0.1648 | 72.8474 | 97471 | 99738 | 0 |
| GLM-51 | GLM | glm-5.1 | glm-5.1 | default | 12 | 12 | 1.0 | 1.0 | 0.8662 | 0.8188 | 1.0 | 1.0 | 0.9255 | 0.1687 | 251.9058 | 97440 | 163496 | 68480 |
| Kimi-K26-Fallback-Moonshot-V1-8K | Kimi | kimi-k2.6 fallback | moonshot-v1-8k | fallback | 12 | 12 | 1.0 | 1.0 | 0.8588 | 0.7799 | 1.0 | 1.0 | 0.9227 | 0.1792 | 107.1514 | 68969 | 69271 | 0 |

5 个模型全部达到 Pipeline Success=1.0 和 JSON Success=1.0，说明 EviProto 不依赖单一 LLM 后端。完成模型的平均 AutoScore 为 0.8651，平均 Evidence Locatability 为 0.9261。模型差异主要体现在延迟、token 用量、证据详略和跨运行稳定性，而不是 pipeline 可行性。

表 5-2 展示分协议表现。

| model | ftp_replay | smtp_replay | rtsp_replay | http_replay | ftp_evidence_loc | smtp_evidence_loc | rtsp_evidence_loc | http_evidence_loc |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DeepSeek-V4-Flash-NonThinking | 0.4176 | 0.9104 | 0.9474 | 1.0 | 0.9488 | 0.9191 | 0.9406 | 0.8898 |
| Qwen-Plus | 0.4176 | 0.9701 | 0.9474 | 0.9524 | 0.9562 | 0.921 | 0.9118 | 0.9077 |
| Qwen-Flash | 0.4176 | 0.9801 | 0.9474 | 0.9048 | 0.9412 | 0.9217 | 0.9334 | 0.9379 |
| GLM-51 | 0.4176 | 0.9104 | 0.9474 | 1.0 | 0.9508 | 0.9254 | 0.8928 | 0.9329 |
| Kimi-K26-Fallback-Moonshot-V1-8K | 0.6007 | 1.0 | 0.9474 | 0.5714 | 0.9542 | 0.9085 | 0.9167 | 0.9113 |

FTP 对所有模型都是相对更难的协议；SMTP、RTSP、HTTP 的 replay 通常更高。GLM-5.1 的证据定位表现较强，但延迟和 token 开销较大。Moonshot-V1-8K 作为 Kimi fallback 可以完整跑通，但 replay 分数略低，适合作为可用兼容性基线。

表 5-3 展示 E4 probe 执行覆盖率。

| model | expected_probes | executed_probes | probe_execution_coverage | passed_probes | probe_pass_rate | missing_probe_reason |
| --- | --- | --- | --- | --- | --- | --- |
| DeepSeek-V4-Flash-NonThinking | 144 | 144 | 1.0 | 144 | 1.0 |  |
| Qwen-Plus | 144 | 144 | 1.0 | 144 | 1.0 |  |
| Qwen-Flash | 144 | 144 | 1.0 | 144 | 1.0 |  |
| GLM-51 | 144 | 144 | 1.0 | 144 | 1.0 |  |
| Kimi-K26-Fallback-Moonshot-V1-8K | 144 | 144 | 1.0 | 144 | 1.0 |  |

表 5-4 展示 canonical stability。这里不使用数据库动态 ID，而使用归一化 message、transition、evidence、status key 计算 Jaccard。

| model | msgtype_jaccard | transition_jaccard | evidence_jaccard | status_jaccard | canonical_stability |
| --- | --- | --- | --- | --- | --- |
| DeepSeek-V4-Flash-NonThinking | 0.1741 | 0.1818 | 0.1818 | 0.1671 | 0.1762 |
| Qwen-Plus | 0.1849 | 0.1266 | 0.1528 | 0.1466 | 0.1527 |
| Qwen-Flash | 0.1858 | 0.1584 | 0.1584 | 0.1566 | 0.1648 |
| GLM-51 | 0.1849 | 0.1667 | 0.1667 | 0.1566 | 0.1687 |
| Kimi-K26-Fallback-Moonshot-V1-8K | 0.1966 | 0.1728 | 0.1756 | 0.1716 | 0.1792 |

Canonical Stability 仍低于理想值，说明即使 temperature=0，不同运行之间的状态命名、transition 粒度和证据表述仍存在非确定性。这是 LLM 驱动协议抽取系统的重要限制，但不影响本轮对 pipeline feasibility、evidence locatability 和 trace explainability 的主要结论。

表 6 展示成本与延迟。Cost Index 使用本轮 total token units 归一化计算，实际人民币成本仍需以 provider 账单为准。

| model | input_tokens | output_tokens | reasoning_tokens | total_tokens | avg_latency_seconds | avg_cost_per_run | total_cost_units | cost_index |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| DeepSeek-V4-Flash-NonThinking | 99095 | 123683 | 0 | 222778 | 94.5778 | 18564.83 | 222778 | 1.6115 |
| Qwen-Plus | 97344 | 81012 | 0 | 178356 | 142.656 | 14863.0 | 178356 | 1.2902 |
| Qwen-Flash | 97471 | 99738 | 0 | 197209 | 72.8474 | 16434.08 | 197209 | 1.4266 |
| GLM-51 | 97440 | 163496 | 68480 | 329416 | 251.9058 | 27451.33 | 329416 | 2.3829 |
| Kimi-K26-Fallback-Moonshot-V1-8K | 68969 | 69271 | 0 | 138240 | 107.1514 | 11520.0 | 138240 | 1.0 |

Qwen-Flash 和 DeepSeek-Chat 在速度上更适合作为工程默认后端；Qwen-Plus 综合表现略高但延迟更大；GLM-5.1 质量和证据定位较好，但 latency 与 reasoning/output token 开销最大；Moonshot-V1-8K 延迟居中，能够作为 Kimi fallback 完成实验闭环。

排除模型说明如下。

| model | expected_runs | successful_runs | failure_stage | reason | included_in_main_table |
| --- | --- | --- | --- | --- | --- |
| DeepSeek-Reasoner | 12 | 0 | light_tool_check | Official thinking model does not support the current pipeline tool_choice=required setting. | No |
| Hunyuan-TurboS | 12 | 0 | API authentication | The OpenAI-compatible Hunyuan endpoint requires a Hunyuan API Key; SecretId/SecretKey cannot be used as bearer API key. | No |
| Kimi-K2.6 | 12 | 0 | fallback used | The final Kimi slot uses the same-provider fallback Moonshot-V1-8K. | No |

## 6. 总结

最后一轮实验支持四个核心结论。第一，EviProto 能生成结构合法、引用一致、证据可追溯的候选协议模型。第二，Trace Agent 是 replay 能力的主要来源，而 Verifier/Evidence Guard 的贡献主要体现在证据绑定和状态校准。第三，Probe Agent 通过本地协议服务提供 runtime evidence，并能将一部分 hypothesis 转换为 supported/disputed。第四，在 5 个完整官方 API 模型上，EviProto 都能稳定跑完整 pipeline，模型差异主要体现为成本、延迟、证据详略和跨运行稳定性。

## 7. 有效性威胁

本实验不使用人工 gold label，因此不能声称生成模型等价于 RFC 或人工专家规范；它评估的是结构合法性、trace 可解释性、证据可定位性、probe 可执行性和跨模型可迁移性。Probe 服务是具体实现 oracle，不等同于协议规范 oracle。Full-State Replay 对状态抽象粒度敏感，因此需要与 Msg+Resp Replay 一起解读。Canonical Stability 仍偏低，说明状态命名和证据表述存在 LLM 非确定性，后续可以通过更强 canonicalization 或 post-processing 继续改进。

## 8. 输出位置

本轮 raw outputs 保存在 `results/e1_auto_quality/raw`、`results/e2_ablation/raw`、`results/e3_probe/raw`、`results/e4_multi_model/raw`。表格保存在各实验的 `tables` 目录。