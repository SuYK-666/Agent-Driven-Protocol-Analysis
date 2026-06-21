# EviProto：面向文本网络协议的多智能体证据绑定分析框架设计与实现

> 面向 FTP、SMTP、RTSP、HTTP 等文本网络协议的多智能体分析原型。EviProto 将协议文档、会话轨迹与种子样本转化为可追溯、可验证、可展示的结构化协议模型。

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-Frontend-61DAFB?logo=react&logoColor=222)
![Vite](https://img.shields.io/badge/Vite-Dev-646CFF?logo=vite&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-Storage-003B57?logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-TBD-lightgrey)

## 项目简介

EviProto 是一个“证据优先”的协议分析框架，目标是降低文本网络协议建模过程中的黑箱程度。系统通过多个专职智能体协作，从协议说明、真实会话轨迹和模糊测试种子中抽取消息格式、字段约束、状态迁移与协议不变量，并为每条结论绑定来源证据、置信度与冲突信息。

项目同时提供命令行实验流水线和 React 可视化界面，便于完成从数据导入、模型生成、证据校验、在线探测到实验评估的完整闭环。

## 核心特性

- 🧠 **多智能体协作**：Spec Agent、Trace Agent、Verifier、Probe Agent 分工处理文档理解、轨迹恢复、证据校验和在线探测。
- 🔗 **证据绑定建模**：协议状态、消息类型、字段约束和不变量均可关联到文档片段、会话观测或探测结果。
- 🧪 **在线探测验证**：对低置信度或存在冲突的结论发起探测，使用真实服务反馈修正模型。
- 🧩 **多协议适配**：通过 `ProtocolAdapter` 机制接入 FTP、SMTP、RTSP、HTTP 等文本协议。
- 📊 **实验结果可复现**：保留 `data/` 与 `results/` 中的实验输入、原始输出和统计表，便于复核与论文写作。
- 🖥️ **可视化分析界面**：前端提供仪表盘、状态机、证据链、探测历史和消息视图。

## 系统架构

```text
┌──────────────────────────────────────────────────────────────┐
│                         React Web UI                         │
│   Dashboard | State Machine | Evidence Chain | Probe History │
└───────────────────────────────┬──────────────────────────────┘
                                │ REST API
┌───────────────────────────────▼──────────────────────────────┐
│                         FastAPI Backend                       │
│                                                              │
│  ┌────────────┐  ┌─────────────┐  ┌──────────┐  ┌─────────┐ │
│  │ Spec Agent │  │ Trace Agent │  │ Verifier │  │  Probe  │ │
│  └────────────┘  └─────────────┘  └──────────┘  └─────────┘ │
│                                                              │
│  Protocol Adapter Registry: FTP | SMTP | RTSP | HTTP         │
│  SQLite Storage + Protocol Model Manager                     │
└──────────────────────────────────────────────────────────────┘
```

## 智能体职责

| 模块             | 主要职责                                             | 关键文件                                        |
| ---------------- | ---------------------------------------------------- | ----------------------------------------------- |
| Spec Agent       | 从协议文档中抽取消息类型、字段约束、顺序规则和不变量 | `backend/app/services/spec_agent_service.py`  |
| Trace Agent      | 从会话轨迹和种子样本中恢复协议状态与迁移关系         | `backend/app/services/trace_agent_service.py` |
| Verifier         | 为模型结论绑定证据、计算置信度并标记冲突             | `backend/app/services/verifier_service.py`    |
| Probe Agent      | 对可运行协议服务发起探测，补充或修正争议结论         | `backend/app/services/probe_service.py`       |
| Adapter Registry | 统一不同文本协议的数据加载、解析和探测接口           | `backend/app/protocols/`                      |

## 支持协议与数据

| 协议 | 当前状态 | 数据来源                              | 说明                               |
| ---- | -------- | ------------------------------------- | ---------------------------------- |
| FTP  | 较完整   | 文档摘要、会话轨迹、ProFuzzBench 种子 | 覆盖登录、目录、文件传输等核心流程 |
| SMTP | 可用     | 文档摘要、会话轨迹、SMTP 种子         | 覆盖问候、认证、邮件发送流程       |
| RTSP | 可用     | 文档摘要、会话轨迹、RTSP 种子         | 关注请求/响应头与会话控制流程      |
| HTTP | 可用     | 文档摘要、会话轨迹、HTTP 种子         | 识别请求方法、响应模式与常见头字段 |

## 目录结构

```text
EviProto/
├── backend/                 # FastAPI 后端与多智能体核心逻辑
│   ├── app/
│   │   ├── api/             # REST API 路由
│   │   ├── core/            # 配置、数据库、LLM 客户端
│   │   ├── models/          # 数据库领域模型
│   │   ├── protocols/       # 协议适配器与注册表
│   │   ├── services/        # 智能体、流水线、证据与探测服务
│   │   └── tools/           # 协议解析与工具函数
│   ├── app/tests/           # 后端测试
│   ├── main.py              # FastAPI 入口
│   └── requirements.txt     # Python 依赖
├── frontend/                # React + Vite 可视化界面
│   ├── public/
│   ├── src/
│   │   ├── api/             # 前端 API 客户端
│   │   ├── components/      # 通用布局与组件
│   │   ├── context/         # 项目上下文
│   │   └── pages/           # 仪表盘、状态机、证据链等页面
│   └── package.json
├── data/                    # 可提交的实验输入与流水线输出
│   ├── docs/                # 协议文档摘要
│   ├── traces/              # 会话轨迹与 ProFuzzBench 种子
│   ├── outputs/             # 协议模型、评估报告、回归报告
│   └── protocol_analysis.db # 示例 SQLite 数据库
├── results/                 # 论文实验原始结果与统计表
├── scripts/                 # 数据导入、实验运行、报告生成与本地协议服务脚本
├── Docs/                    # 设计文档、任务拆解与论文写作材料
└── .env.example             # 环境变量模板
```

## 快速开始

### 1. 准备环境

- Python 3.11+
- Node.js 18+
- OpenAI 兼容接口的 LLM 服务，或脚本中支持的其他模型服务

### 2. 配置后端

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
cd ..
copy .env.example .env
```

编辑根目录 `.env`，填入模型服务配置：

```env
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o
DATABASE_URL=sqlite:///./data/protocol_analysis.db
```

macOS / Linux 可使用：

```bash
cp .env.example .env
```

### 3. 配置前端

```bash
cd frontend
npm install
cd ..
```

### 4. 启动 Web 系统

```bash
cd backend
uvicorn main:app --reload --port 8000
```

另开终端：

```bash
cd frontend
npm run dev
```

访问 `http://localhost:5173` 查看可视化界面；后端接口文档位于 `http://localhost:8000/docs`。

## 命令行实验

运行单协议完整分析：

```bash
python scripts/run_full_analysis.py FTP
python scripts/run_full_analysis.py SMTP
python scripts/run_full_analysis.py RTSP
python scripts/run_full_analysis.py HTTP
```

启动本地协议服务用于探测：

```bash
python scripts/start_ftp_server.py
python scripts/start_smtp_server.py
python scripts/start_rtsp_server.py
python scripts/start_http_server.py
```

运行论文实验集合：

```bash
python scripts/run_paper_experiments.py
```

生成中文实验报告：

```bash
python scripts/generate_final_chinese_report.py
```

## 实验产物

仓库保留实验数据，便于 GitHub 提交后直接复核结果：

- `data/docs/`：协议说明摘要。
- `data/traces/`：手工整理会话轨迹与 ProFuzzBench 原始种子。
- `data/outputs/`：流水线生成的协议结构、种子、评估报告和回归报告。
- `results/e1_auto_quality/`：自动化建模质量实验。
- `results/e2_ablation/`：消融实验。
- `results/e3_probe/`：在线探测收益实验。
- `results/e4_multi_model/`：多模型对比实验。
- `results/experiment_report_final_zh.md`：中文实验总结报告。

## 开发与测试

后端测试：

```bash
cd backend
pytest
```

前端构建：

```bash
cd frontend
npm run build
```

前端代码检查：

```bash
cd frontend
npm run lint
```

## 项目定位

EviProto 目前是面向课程项目、科研原型和论文实验的可运行系统。它强调：

- 可运行：提供后端、前端、脚本和示例数据库；
- 可解释：协议模型与智能体结论均绑定证据；
- 可复核：实验输入、原始输出和统计结果随仓库保留；
- 可扩展：新文本协议可通过适配器注册到统一流水线。

## 许可证

当前仓库尚未声明许可证。公开发布前建议补充 `LICENSE` 文件，并在上方徽章中替换为实际许可证类型。
