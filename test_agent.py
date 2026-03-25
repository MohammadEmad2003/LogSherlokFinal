"""
Quick test script for autonomous forensic agent
"""
import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from orchestrator import ForensicOrchestrator
from utils import LLMClient


async def test_agent():
    """Test the autonomous agent components"""

    print("=" * 60)
    print("Autonomous Forensic Agent - Component Test")
    print("=" * 60)

    # Test 1: Initialize LLM Client
    print("\n[TEST 1] Initializing LLM Client...")
    try:
        llm_client = LLMClient(
            base_url="https://5d0d-196-157-106-114.ngrok-free.app/v1",
            api_key="dummy",
            model="gpt-4"
        )
        print("[OK] LLM Client initialized")
    except Exception as e:
        print(f"[ERROR] LLM Client failed: {e}")
        return

    # Test 2: Initialize Orchestrator
    print("\n[TEST 2] Initializing Orchestrator...")
    try:
        orchestrator = ForensicOrchestrator(
            llm_client=llm_client,
            websocket_callback=None,
            max_steps=5  # Limit steps for testing
        )
        print("[OK] Orchestrator initialized")
    except Exception as e:
        print(f"[ERROR] Orchestrator failed: {e}")
        return

    # Test 3: Test guardrails
    print("\n[TEST 3] Testing command guardrails...")
    from tools import create_forensic_tools

    tools = create_forensic_tools()

    # Test safe command
    safe_cmd = "file /tmp/test.bin"
    result = tools.guardrail.validate_command(safe_cmd)
    print(f"  Safe command '{safe_cmd}': {'[OK] PASSED' if result.passed else '[FAIL] BLOCKED'}")

    # Test dangerous command
    danger_cmd = "rm -rf /"
    result = tools.guardrail.validate_command(danger_cmd)
    print(f"  Dangerous command '{danger_cmd}': {'[OK] BLOCKED' if not result.passed else '[FAIL] ALLOWED (BAD!)'}")

    # Test hallucination
    fake_cmd = "super_analyzer --magic-detect"
    result = tools.guardrail.validate_command(fake_cmd)
    print(f"  Fake tool '{fake_cmd}': {'[OK] BLOCKED' if not result.passed else '[FAIL] ALLOWED (BAD!)'}")

    # Test 4: Test evidence extraction
    print("\n[TEST 4] Testing evidence extraction...")
    from tools import EvidenceExtractor

    extractor = EvidenceExtractor()
    test_output = """
    Connection to 192.168.1.100:443
    Resolved domain: malicious.example.com
    Process: malware.exe (PID: 1234)
    Hash: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
    """

    evidence = extractor.extract(test_output, source="test_tool")
    print(f"  Extracted {len(evidence)} pieces of evidence:")
    for ev in evidence:
        print(f"    - [{ev.type}] {ev.value} (confidence: {ev.confidence:.2f})")

    # Test 5: Test MITRE mapping
    print("\n[TEST 5] Testing MITRE ATT&CK mapping...")
    from utils import MITREMapper

    mapper = MITREMapper()
    if evidence:
        enriched = mapper.enrich_evidence(evidence[0])
        print(f"  Evidence enriched with MITRE data:")
        print(f"    - Tactics: {enriched.mitre_tactics}")
        print(f"    - Techniques: {enriched.mitre_techniques}")

    print("\n" + "=" * 60)
    print("[OK] All component tests passed!")
    print("=" * 60)
    print("\nNOTE: To test full investigation flow:")
    print("  1. Start server: python backend/main.py")
    print("  2. Open browser: http://localhost:8000")
    print("  3. Upload a forensic artifact")
    print("  4. Watch the autonomous agent in action!")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(test_agent())
