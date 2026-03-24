# Autonomous Forensic Orchestrator - Web Interface

A fully functional web-based DFIR (Digital Forensics and Incident Response) platform that simulates an autonomous forensic agent pipeline.

## Architecture

```
/ui                     # Frontend (HTML, CSS, JavaScript)
├── index.html          # Landing page with file upload
├── dashboard.html      # Real-time investigation dashboard
├── styles.css          # Cybersecurity dark theme styling
├── app.js              # Landing page logic
└── dashboard.js        # Dashboard WebSocket & UI logic

/backend                # FastAPI server
├── main.py             # Application entry point
├── requirements.txt    # Python dependencies
└── services/
    ├── session_manager.py      # Investigation session management
    ├── websocket_manager.py    # Real-time WebSocket handling
    ├── mock_agent.py           # Forensic agent simulation
    └── report_generator.py     # Report generation (JSON, HTML, STIX)
```

## Features

### Real-Time Investigation Dashboard

- **Live Steps Feed**: Watch the agent's thought process, actions, and tool execution in real-time
- **Evidence Collection**: See IOCs and artifacts as they're discovered
- **Attack Timeline**: Chronological view of attack events
- **MITRE ATT&CK Mapping**: Automatic technique mapping as analysis progresses
- **Attack Hypotheses**: AI-generated hypotheses with confidence scores
- **Agent Instructions**: Send guidance to the forensic agent during analysis

### Supported Forensic Tools (Simulated)

| Category                | Tools                                                                                        |
| ----------------------- | -------------------------------------------------------------------------------------------- |
| **Memory Forensics**    | Volatility3 (pslist, pstree, malfind, netscan, cmdline, dlllist, handles, svcscan, registry) |
| **Disk Forensics**      | Plaso (log2timeline, psort), Sleuth Kit (fls, icat)                                          |
| **Windows Forensics**   | Chainsaw, Hayabusa, EvtxECmd, PECmd, RECmd                                                   |
| **Linux Forensics**     | ausearch, journalctl, osquery                                                                |
| **Malware Analysis**    | YARA, FLOSS, PE/ELF Analysis, Strings                                                        |
| **Binary Analysis**     | Capstone (disassembly), Unicorn (emulation), angr (symbolic execution)                       |
| **Document Analysis**   | OLE Tools, RTF Analysis, PDF Analysis                                                        |
| **Network Forensics**   | PCAP Analysis, Zeek                                                                          |
| **Threat Intelligence** | MalwareBazaar, Feodo Tracker, URLhaus, AlienVault OTX                                        |
| **MITRE Mapping**       | Technique lookup, Forensic event mapping                                                     |

### Report Generation

- **JSON Report**: Complete investigation data in structured JSON
- **HTML Report**: Professional styled report with all findings
- **STIX 2.1 Bundle**: Standard threat intelligence format for sharing

## Quick Start

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Start the Server

```bash
# From project root
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Or using the main.py directly:

```bash
cd backend
python main.py
```

### 3. Access the Interface

Open your browser and navigate to:

- **Landing Page**: http://localhost:8000/
- **API Docs**: http://localhost:8000/docs (Swagger UI)

## API Endpoints

| Method      | Endpoint                 | Description                                     |
| ----------- | ------------------------ | ----------------------------------------------- |
| `POST`      | `/upload_artefact`       | Upload forensic artifact to start investigation |
| `POST`      | `/chat`                  | Send instruction to the agent                   |
| `GET`       | `/status/{session_id}`   | Get investigation status                        |
| `GET`       | `/report/{session_id}`   | Get final report (format: json, html, stix)     |
| `GET`       | `/sessions`              | List all active sessions                        |
| `DELETE`    | `/session/{session_id}`  | Delete a session                                |
| `GET`       | `/tools`                 | List all available forensic tools               |
| `GET`       | `/health`                | Health check                                    |
| `WebSocket` | `/ws/agent/{session_id}` | Real-time investigation updates                 |

## WebSocket Messages

### Server → Client

| Type             | Description                                                                          |
| ---------------- | ------------------------------------------------------------------------------------ |
| `step`           | New analysis step with full details (thought, action, tool, input, output, evidence) |
| `evidence`       | New evidence discovered                                                              |
| `progress`       | Progress update (percentage, phase)                                                  |
| `timeline_event` | New event added to attack timeline                                                   |
| `mitre_mapping`  | New MITRE technique mapped                                                           |
| `hypothesis`     | New attack hypothesis generated                                                      |
| `complete`       | Investigation completed with summary                                                 |
| `error`          | Error occurred                                                                       |

### Client → Server

| Type          | Description                    |
| ------------- | ------------------------------ |
| `instruction` | User instruction for the agent |
| `pause`       | Pause investigation            |
| `resume`      | Resume investigation           |
| `stop`        | Stop investigation             |

## Step Schema

Each analysis step follows this structure:

```json
{
    "step_id": "uuid",
    "step_number": 1,
    "timestamp": "ISO8601",
    "phase": "analysis | enrichment | detection | correlation",
    "thought": "Why this step is needed",
    "action": "What the agent decides to do",
    "tool": "Tool name",
    "tool_category": "Category (memory_forensics, malware_analysis, etc.)",
    "input": {
        "source": "artifact | previous_step",
        "data": "input details"
    },
    "output": {
        "raw": "tool raw output",
        "parsed": "structured data"
    },
    "evidence": [
        {
            "type": "ip | domain | hash | process | file | registry",
            "value": "extracted value",
            "confidence": 0.85,
            "mitre_techniques": ["T1059.001"],
            "threat_score": 0.9
        }
    ],
    "next_step_reasoning": "Why next step is chosen",
    "duration_ms": 1500
}
```

## Investigation Phases

1. **Analysis** (0-20%): Initial artifact triage with appropriate tools
2. **Deep Analysis** (20-40%): Detailed examination based on findings
3. **Enrichment** (40-55%): Threat intelligence correlation
4. **Detection** (55-70%): MITRE ATT&CK mapping
5. **Correlation** (70-85%): Timeline building and evidence correlation
6. **Hypothesis** (85-95%): Attack hypothesis generation
7. **Complete** (95-100%): Final report generation

## Development

### Project Structure

```
backend/
├── __init__.py
├── main.py                 # FastAPI app, routes, endpoints
├── requirements.txt
├── api/
│   └── __init__.py
└── services/
    ├── __init__.py
    ├── session_manager.py  # Session state management
    ├── websocket_manager.py # WebSocket connection handling
    ├── mock_agent.py       # Agent simulation logic
    └── report_generator.py # Report generation (JSON, HTML, STIX)
```

### Adding New Tools

To add a new tool to the mock agent:

1. Add the tool definition to `MockForensicAgent.TOOLS` in `mock_agent.py`
2. Add the tool to appropriate phase in `_get_phase_tools()`
3. Create an output generator function `_generate_*_output()`

### Customizing Reports

Modify `report_generator.py` to:

- Add new report formats
- Customize HTML styling
- Add additional STIX object types

## Contributing

This is part of the Hackathon Challenge 4: Autonomous Forensic Agent

## License

Part of the CAI (Cybersecurity AI) project.
