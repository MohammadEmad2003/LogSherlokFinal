# 🕵️‍♂️ LogSherlok
**Autonomous Digital Forensics & Incident Response (DFIR) Platform**

Here is a Drive link for our 2-min Demo video : [LogSherlok Demo Video](https://drive.google.com/drive/folders/1eB5MKIMI-4OKv-jZ8zlRrr0RDE2lWltD?usp=drive_link)

LogSherlok is an AI-powered Digital Forensics and Incident Response orchestration platform. It is built as a highly specialized wrapper on top of the [CAI (Cybersecurity AI) framework](https://github.com/aliasrobotics/cai) and brings a complete visual dashboard, real-time investigation streaming, and customized forensic capabilities to automate the analysis of digital evidence.

⚠️ **Compatibility Notice:** Due to underlying forensic tool dependencies and shell execution parameters, LogSherlok is strictly designed to run on **Kali Linux** or **Windows Subsystem for Linux (WSL)**.

---

## 🏗️ Architecture

LogSherlok's architecture is a multi-layered system designed to bridge large language model reasoning with deep, low-level forensic tool execution. At its core, it seamlessly unifies a visually rich UI, a FastAPI backend, an Orchestrator state-machine, and the specialized CAI DFIR agent.

### System Overview Diagram

```mermaid
graph TD;
    subgraph UI["Frontend Dashboard"]
        A[Visual Dashboard Interface]
        B[Real-time Terminal Stream]
        C[MITRE ATT&CK Map]
        L[Agent Chat Interface]
    end

    subgraph BE["Backend Services (FastAPI)"]
        D[REST API Manager]
        E[WebSocket Manager]
        F[Forensic Orchestrator Engine]
    end

    subgraph CAI["CAI Framework"]
        G[DFIR Agent]
        H[Runner Engine]
    end

    subgraph Tools["Forensic Toolkits"]
        I[DISC.py - Disk Forensics]
        J[Volatility 3 - Memory]
        K[Yara & Generic Linux Utils]
    end

    A <-->|HTTP/REST| D
    B <-->|WebSockets| E
    C <-->|WebSockets| E
    L <-->|HTTP/REST| D

    D --> F
    E <--> F
    F <-->|Prompts, Context & State| G
    G -->|Execution Path| H
    H -->|Function Invocation| I
    H -->|Function Invocation| J
    H -->|Process Execution| K
```

### 🧠 The Forensic Orchestrator Engine
The Orchestrator (`backend/orchestrator.py`) is the brain of the platform. Instead of letting the AI agent run passively, the Orchestrator wraps the CAI agent in a highly controlled, iterative incident-response loop.

**Orchestrator Workflow:**
1. **State Initialization:** When a new artifact (e.g., `.mem`, `.E01`, `.pcap`) is uploaded, the Orchestrator initializes a `StateManager` to safely track investigation steps, newly found evidence, and MITRE hypotheses.
2. **Real-time Terminal Interception:** A custom `TerminalStream` class hijacks the standard Python runtime's `sys.stdout` and `sys.stderr`. As the underlying CAI agent outputs "thinking" chunks or begins executing CLI tools, the Orchestrator dynamically streams these directly to the UI over WebSockets.
3. **Iterative Analysis Loop:** 
    - The Orchestrator constructs a context-rich prompt integrating *Current Analysis State*, *Prior Extracted Evidence*, and *Pending Tool execution requests*.
    - It triggers `Runner.run()` targeting the DFIR Agent.
    - Post-execution, the Orchestrator parses the agent's raw text to extract actionable facts (IOCs, IPs, Malicious processes) via validation engines.
    - Finally, evidence is probabilistically mapped by the Orchestrator to the **MITRE ATT&CK** framework, providing a full chronological view of the adversarial breach.

### 🤖 The DFIR Agent
Built seamlessly utilizing the core concepts of the CAI framework (`src/cai/agents/dfir.py`), the **DFIR Agent** acts as the autonomous forensic investigator.
*   **Instruction Tuning:** It has been primed strictly as a Senior Incident Responder minimizing LLM hallucination by forcing a reliance strictly defined forensic output parsers rather than generated assumptions.
*   **Reasoning Blocks:** Utilizing custom `think` actions, the agent breaks artifacts down into component parts (e.g., locating obfuscated PowerShell -> strings extraction -> executing safe sandbox deobfuscation -> malicious hypothesis testing).
*   **State Awareness:** It relies on the Orchestrator to maintain conversation history ensuring long-running disk forensic analysis isn't bottlenecked by short-context windows.

### 🛠️ Dedicated Forensic Tooling
LogSherlok breaks free from "typical" code execution setups by hardlinking specialized digital forensics suites directly into the agent's function-calling registry inside `src/cai/tools/forensics_salamanca/`:

*   **`DISC.py` (Disk Analysis Module):** Custom capabilities integrated for raw disk image ingestion.
    *   `run_tsk_mft`: Leverages The Sleuth Kit (TSK) `fls` to extract Master File Table (MFT) data seamlessly from mounted images to identify deleted and cloaked assets.
    *   `run_plaso`: Bootstraps the Plaso (`log2timeline` / `psort`) toolkit to auto-generate chronological timelines across whole disks, returning CSV results directly to the LLM agent for timeline evaluation.
*   **Memory Forensics (`VOLATILITY3.py`):** Connects `vol.py` natively allowing the agent to perform `windows.pslist`, `windows.malfind`, and network socket extractions on-demand upon `.mem` artifacts.
*   **Malware Sandboxing (`YARA.py`):** Enables prompt-based dynamic YARA rule execution.
*   **Reconnaissance & System Utilities:** Inherited from the core CAI framework logic like `generic_linux_command` enabling strictly sandboxed CLI execution bounds for `tcpdump`, `strings`, `binwalk`, or similar built-in tools.

---

## 🚀 Getting Started

### Prerequisites
* **OS:** Kali Linux OR Windows Subsystem for Linux (WSL). (Do not use natively on Windows or macOS).
* **Environment:** Python 3.10+, a PostgreSQL database (e.g., Neon Postgres), and an accessible OpenAI-compatible LLM endpoint.
* **Forensic Software:** Ensure tools like Sleuth Kit (`tsk`), Plaso, and Volatility 3 are organically installed on your OS if you plan to do deep disk/memory analysis.

### 1. Clone the Repository
```bash
git clone <repository-url> logsherlok
cd logsherlok
```

### 2. Install Dependencies
LogSherlok requires extensive backend packages including DB connectors and python security frameworks. Using `--break-system-packages` is generally necessary on modern Kali/Debian 12 setups without Virtual Environments.

```bash
python3 -m pip install -r backend/requirements.txt --break-system-packages
python3 -m pip install cai-framework
python3 -m pip install -r requriments.txt
python3 -m pip install sqlalchemy psycopg2-binary passlib bcrypt python-jose python-multipart pydantic-settings python-dotenv --break-system-packages
```

### 3. Configure the Environment
Create a `.env` file in the root of the project with the following (or use the one already present):

```env
# Database Configuration
DATABASE_URL=postgresql://user:password@cloud-db-provider/.../neondb?sslmode=require

# External LLM / CAI Setup
OPENAI_BASE_URL=https://5d0d-196-157-106-114.ngrok-free.app/
OPENAI_API_KEY=sk-123                  # Can be dummy text for local uncensored models
CAI_MODEL=gpt-4                        # The AI model identifier
```

### 4. Run the Server
Use the unified runner script to start the FastAPI server and WebSocket managers:

```bash
python3 run_server.py
```

### 5. Access the Dashboard
Navigate your browser to:
[http://localhost:8000/](http://localhost:8080/)

1. Register an account natively on the page.
2. Upload a forensic artifact (like a disk image, memory dump, or log file).
3. The Orchestrator will seamlessly spawn the `DFIR Agent` and start iterating through the solve loops. 
4. Check the **Terminal Logs Panel** on the left to watch exactly what the program is executing and thinking!
