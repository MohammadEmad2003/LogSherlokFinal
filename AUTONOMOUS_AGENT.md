# Autonomous Forensic Orchestrator

An AI-powered autonomous forensic investigation system that uses the ReAct (Reason → Act → Observe) pattern to perform digital forensic analysis with minimal human intervention.

## 🎯 Overview

This system implements an autonomous forensic agent that:
- **Reasons** about artifacts using LLM-powered analysis
- **Acts** by executing forensic tools and commands
- **Observes** results and extracts evidence
- **Adapts** investigation strategy dynamically based on findings
- **Protects** against hallucinations and unsafe operations with guardrails

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     FastAPI Backend                      │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │ Orchestrator │───▶│ LLM Client   │───▶│ OpenAI    │ │
│  │  (ReAct)     │    │              │    │ Compatible│ │
│  └──────┬───────┘    └──────────────┘    │  API      │ │
│         │                                 └───────────┘ │
│         ▼                                               │
│  ┌─────────────┐    ┌──────────────┐                  │
│  │  Forensic   │───▶│  Guardrails  │                  │
│  │   Tools     │    │   & Safety   │                  │
│  └─────────────┘    └──────────────┘                  │
│         │                                               │
│         ▼                                               │
│  ┌─────────────────────────────────────────────────┐  │
│  │         Evidence Extraction & MITRE Mapping      │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │   WebSocket      │
              │   Dashboard      │
              └──────────────────┘
```

## 📁 Project Structure

```
Forensics-Agent/
├── backend/
│   ├── main.py              # FastAPI application & endpoints
│   ├── schemas.py           # Pydantic v2 data models
│   ├── orchestrator.py      # ReAct loop implementation
│   ├── tools.py             # Command execution & guardrails
│   ├── utils.py             # LLM client, MITRE mapper, helpers
│   └── services/            # Legacy mock services (for compatibility)
├── ui/
│   ├── index.html           # Landing page
│   ├── dashboard.html       # Investigation dashboard
│   ├── app.js               # Landing page logic
│   ├── dashboard.js         # Dashboard interactivity
│   └── styles.css           # Styling
├── uploads/                 # Uploaded artifacts storage
├── reports/                 # Generated reports
├── requirements.txt         # Python dependencies
└── AUTONOMOUS_AGENT.md     # This file
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

### 2. Configure LLM Endpoint

Set environment variables for LLM access:

```bash
# Using ngrok endpoint
export LLM_BASE_URL="https://a3d7-196-157-8-24.ngrok-free.app/v1"
export LLM_API_KEY="dummy"
export LLM_MODEL="gpt-4"
```

Or add to `.env` file:

```env
LLM_BASE_URL=https://a3d7-196-157-8-24.ngrok-free.app/v1
LLM_API_KEY=dummy
LLM_MODEL=gpt-4
```

### 3. Run the Server

```bash
# Start FastAPI server
python backend/main.py

# Or with uvicorn directly
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Access the UI

Open your browser to:
- **Landing Page**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## 🔧 API Endpoints

### Upload Artifact
```http
POST /upload_artefact
Content-Type: multipart/form-data

file: <forensic_artifact>
artifact_type: memory_dump | disk_image | pcap | evtx | malware_sample | auto
description: "Optional description of the incident"
```

**Response:**
```json
{
  "session_id": "abc12345",
  "status": "started",
  "message": "Investigation initialized...",
  "artifact_name": "memory.raw",
  "artifact_size": 1073741824
}
```

### WebSocket Investigation Stream
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/agent/abc12345');

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);

  switch(msg.type) {
    case 'step':      // New investigation step
    case 'evidence':  // Evidence discovered
    case 'hypothesis': // Attack hypothesis generated
    case 'todo':      // Todo list updated
    case 'complete':  // Investigation complete
    case 'error':     // Error occurred
  }
};

// Send LLM query
ws.send(JSON.stringify({
  type: 'llm_query',
  message: 'What processes are connecting to external IPs?'
}));
```

### Chat Endpoint
```http
POST /chat
Content-Type: application/json

{
  "session_id": "abc12345",
  "message": "Focus on network connections"
}
```

### List Sessions
```http
GET /sessions
```

## 🧩 Core Components

### 1. **Orchestrator** (`orchestrator.py`)

Implements the ReAct pattern:

```python
async def _react_loop(self, session_id: str):
    while should_continue_investigation(state, max_steps):
        # REASON: Determine next action using LLM
        reasoning = await self._reason_phase(state)

        # ACT: Execute forensic command/tool
        action_result = await self._act_phase(state, reasoning)

        # OBSERVE: Extract evidence and insights
        observation = await self._observe_phase(state, action_result)

        # Update state, hypotheses, todos
        await self._update_state(state, observation)
```

### 2. **Tools** (`tools.py`)

Safe command execution with guardrails:

```python
class CommandGuardrail:
    def validate_command(self, command: str) -> GuardrailCheck:
        # ✓ Block dangerous commands
        # ✓ Allow only forensic tools
        # ✓ Detect command injection
        # ✓ Loop detection
        # ✓ Failure limits

class EvidenceExtractor:
    def extract(self, output: str) -> List[Evidence]:
        # Extract IPs, domains, hashes, processes, etc.
        # Map to MITRE ATT&CK framework
```

### 3. **LLM Client** (`utils.py`)

OpenAI-compatible API integration:

```python
class LLMClient:
    async def generate_reasoning(self, context: Dict) -> ModelOutput:
        # Builds context-aware prompt with:
        # - Artifact info
        # - Evidence found so far
        # - Recent observations
        # - Investigation phase
        # - Pending todos

        # Returns structured JSON:
        {
          "reasoning": "...",
          "action": "vol.py -f memory.raw windows.pslist",
          "action_type": "command",
          "expected_output": "...",
          "confidence": 0.85,
          "should_continue": true,
          "priority": "high"
        }
```

### 4. **Schemas** (`schemas.py`)

Pydantic v2 models for type safety:

- `ForensicScenario` - Initial investigation context
- `AgentStep` - Single ReAct cycle step
- `Evidence` - Discovered evidence with MITRE mapping
- `ModelOutput` - Structured LLM response
- `FullState` - Complete investigation state
- `AttackHypothesis` - Generated attack theories
- `TodoItem` - Dynamic task management

## 🛡️ Safety & Guardrails

### Command Safety
- **Blocked Operations**: `rm -rf /`, `dd if=/dev/zero`, fork bombs, `shutdown`, `wget`, `curl`
- **Allowed Tools**: Only forensic tools (volatility, strings, grep, tshark, etc.)
- **Injection Prevention**: Blocks `;`, `&&`, `||`, `` ` ``, `$()`
- **Timeout**: 300 seconds max per command

### Hallucination Detection
- Checks for non-existent tools (e.g., `super_analyzer`, `magic_tool`)
- Flags overconfident reasoning without evidence
- Validates commands against known tool list

### Loop Prevention
- Detects repeated commands (>3 times in 10-step window)
- Limits consecutive failures (max 5)
- Progress-based investigation phases

## 📊 Supported Artifact Types

| Type | Extensions | Tools Used |
|------|-----------|------------|
| **Memory Dump** | `.raw`, `.mem`, `.dmp`, `.vmem` | Volatility3, strings |
| **Disk Image** | `.img`, `.dd`, `.E01` | Sleuth Kit (mmls, fls, icat) |
| **Network Capture** | `.pcap`, `.pcapng` | tshark, tcpdump |
| **Event Logs** | `.evtx` | evtx_dump, Chainsaw |
| **Malware Sample** | `.exe`, `.dll` | file, strings, YARA, exiftool |

## 🎯 Investigation Phases

The agent progresses through these phases automatically:

1. **Initialization** → Basic artifact identification
2. **Initial Analysis** → Broad overview of contents
3. **Deep Analysis** → Focus on suspicious findings
4. **Threat Hunting** → Specific IOC hunting
5. **Correlation** → Connect evidence pieces
6. **Complete** → Generate final report

## 📝 Dynamic To-Do System

The agent maintains a dynamic task list:

```json
{
  "id": "a1b2c3d4",
  "task": "Extract process list and identify suspicious processes",
  "priority": "high",
  "status": "pending",
  "rationale": "Need to understand execution artifacts",
  "created_at": "2025-01-15T10:30:00Z"
}
```

Tasks are:
- **Auto-generated** based on artifact type
- **Dynamically added** when new evidence is found
- **Prioritized** by criticality (critical > high > medium > low)
- **Tracked** through completion

## 🎨 Dashboard Features

The web UI provides:

- **Real-time Updates** via WebSocket
- **Network Graph** showing evidence relationships
- **MITRE ATT&CK Matrix** with technique highlighting
- **Charts** for threat scoring, evidence distribution
- **LLM Chat** for natural language queries
- **Live Todo List** showing agent's current focus
- **Evidence Cards** with filtering and search
- **Keyboard Shortcuts** (1-4: views, F: fullscreen, S: sound, E: export)

## 🔍 Example Investigation Flow

```
1. Upload memory.raw → AUTO-DETECTED as memory_dump
2. Agent REASONS: "Should identify running processes first"
3. Agent ACTS: vol.py -f memory.raw windows.pslist
4. Agent OBSERVES: Found 47 processes, 3 suspicious (powershell.exe, cmd.exe)
5. Evidence Extracted: 3 processes + confidence scores
6. Hypothesis Generated: "Possible PowerShell-based attack"
7. Todo Added: "Analyze PowerShell command history"
8. Agent REASONS: "Need to check network connections"
9. Agent ACTS: vol.py -f memory.raw windows.netscan
10. Agent OBSERVES: Found 12 external IPs
11. Evidence Extracted: 12 IPs mapped to C2 tactic
12. Hypothesis Updated: "C2 communication detected" (confidence: 0.82)
...continues until investigation complete
```

## 🧪 Testing

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/

# Test specific component
pytest tests/test_orchestrator.py -v
```

## 🐛 Troubleshooting

### LLM Connection Fails
```bash
# Check LLM endpoint
curl -X POST https://a3d7-196-157-8-24.ngrok-free.app/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}'
```

### Forensic Tools Not Found
```bash
# Install Volatility3
pip install volatility3

# Install Sleuth Kit (Ubuntu/Debian)
sudo apt-get install sleuthkit

# Install tshark
sudo apt-get install tshark
```

### WebSocket Disconnects
- Check firewall rules
- Increase timeout in dashboard.js
- Verify session_id is valid

## 📚 References

- **ReAct Pattern**: [Yao et al. 2023](https://arxiv.org/abs/2210.03629)
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Volatility3**: https://github.com/volatilityfoundation/volatility3
- **Pydantic v2**: https://docs.pydantic.dev/2.0/

## 📄 License

MIT License - See LICENSE file for details

---

Built with ❤️ for autonomous digital forensics
