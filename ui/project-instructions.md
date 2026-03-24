# 🧠 Autonomous Forensic Orchestrator (Mock Mode)

## Full Implementation Specification (UI + Backend + Mock Agent)

---

# 🎯 Objective

Build a **fully functional web-based DFIR platform** that simulates an autonomous forensic agent pipeline.

⚠️ IMPORTANT:

- There is NO real AI agent yet
- The system MUST behave as if the agent exists
- All outputs are **mocked but realistic, structured, and logically consistent**

---

# 🧱 System Architecture

```
/ui        → Frontend (HTML, CSS, JS)
/backend   → FastAPI server
  ├── main.py
  ├── api/
  ├── services/
  │     ├── mock_agent.py
  │     ├── session_manager.py
  │     ├── websocket_manager.py
  │     └── report_generator.py
```

---

# 🔁 Core Concept: Simulated ReAct Loop

Each investigation MUST simulate this loop:

```
THOUGHT → ACTION → TOOL → INPUT → OUTPUT → EVIDENCE → NEXT STEP
```

---

# 🧠 Mock Agent Engine (CRITICAL)

## File: `/backend/services/mock_agent.py`

### Responsibilities:

- Generate realistic forensic steps
- Maintain investigation state
- Simulate delays (1–2 seconds per step)
- Stream updates via WebSocket

---

## 🧪 Step Structure (STRICT FORMAT)

Each step MUST follow this schema:

```json
{
    "step_id": "uuid",
    "timestamp": "ISO8601",
    "phase": "analysis | enrichment | detection | correlation",
    "thought": "Why this step is needed",
    "action": "What the agent decides to do",
    "tool": "strings | yara | volatility | enrich_ioc | timeline_builder",
    "input": {
        "source": "artifact | previous_step",
        "data": "input data"
    },
    "output": {
        "raw": "tool raw output",
        "parsed": "structured data"
    },
    "evidence": [
        {
            "type": "domain | ip | hash | process",
            "value": "evil.com",
            "confidence": 0.8
        }
    ],
    "next_step_reasoning": "Why next step is chosen"
}
```

---

# 🧰 Supported Tools (Mocked)

## 1. strings

- Extracts readable strings
- Output: domains, URLs, suspicious text

## 2. yara

- Detect malware signatures
- Output: malware family

## 3. volatility

- Process listing
- Network connections

## 4. enrich_ioc (REAL)

- Use your real implementation

## 5. timeline_builder

- Correlate events

---

# 🔄 Example Investigation Flow

## Step 1 — Strings Extraction

- Tool: strings
- Output: evil.com

## Step 2 — IOC Enrichment

- Tool: enrich_ioc
- Input: evil.com
- Output: malicious domain

## Step 3 — YARA Scan

- Tool: yara
- Output: Emotet detected

## Step 4 — Volatility Analysis

- Tool: volatility
- Output: suspicious process

## Step 5 — Correlation

- Combine all findings

---

# 🌐 Backend API

## POST `/upload_artefact`

Start investigation

Response:

```
{
  "session_id": "abc123",
  "status": "started"
}
```

---

## POST `/chat`

Inject user instruction

---

## GET `/report/{session_id}`

Return final report

---

## WebSocket `/ws/agent`

Streams:

- Steps
- Full state

---

# 📊 Frontend UI (/ui)

## Pages

### index.html

- Upload form

### dashboard.html

## Components

### 1. Live Steps Feed

Shows:

- Thought
- Action
- Tool
- Input
- Output

### 2. Evidence Panel

- Extracted IOCs

### 3. Progress Bar

### 4. Timeline View

### 5. Chat Panel

### 6. Final Report Viewer

---

# 🎨 UI Design (Cybersecurity Style)

- Dark theme
- Neon highlights
- Terminal-like logs

---

# 🧾 Final Report Structure

## JSON

```json
{
    "summary": "Malware infection detected",
    "timeline": [],
    "iocs": [],
    "mitre": [],
    "conclusion": "System compromised"
}
```

---

# 🧬 STIX Integration

- Use your real `build_stix_bundle`
- Convert findings to STIX

---

# 🚀 Implementation Steps

1. Build FastAPI server
2. Create WebSocket manager
3. Implement mock agent
4. Build UI pages
5. Connect WebSocket
6. Simulate steps
7. Generate report

---

# ✅ Expected Result

- Fully working UI
- Live agent simulation
- Realistic forensic pipeline
- Final report + STIX

---

# 🔥 Notes

- All data must be consistent
- No random nonsense
- Steps must logically connect

---

END
