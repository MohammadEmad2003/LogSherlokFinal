#!/usr/bin/env python3
import subprocess
import tempfile
import os
from contextlib import contextmanager
import sys
import openai

# تعديل المسار هنا لو yara.exe موجود في مكان مختلف عندك
YARA_EXE = r"C:\Tools\yara\yara.exe"  # ضع هنا المسار الكامل للـ yara.exe

# حل مشكلة imports لو مش موجود cai.sdk
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../../")))
try:
    from cai.sdk.agents import function_tool, custom_span, trace
except ImportError:
    def function_tool(f): return f
    def custom_span(*args, **kwargs):
        class DummySpan:
            span_data = type("data", (), {})()
            def __enter__(self): return self
            def __exit__(self, exc_type, exc_val, exc_tb): return False
            def set_error(self, err): pass
        return DummySpan()
    def trace(*args, **kwargs):
        class DummyTrace:
            def __enter__(self): return self
            def __exit__(self, exc_type, exc_val, exc_tb): return False
        return DummyTrace()

@function_tool
def generate_yara_rule_from_file(sample_path: str) -> str:
    print(f"[INFO] Generating YARA rule for {sample_path}")
    with open(sample_path, "rb") as f:
        content = f.read()  # اقرأ كل الملف

    prompt = f"""
You are a malware analyst. Generate a YARA rule for the following binary content (hex or string representation):

{content[:4096]}  # فقط أول 4KB لو كبير جدًا

The rule should be valid YARA syntax, include strings, and a descriptive name.
"""

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0
        )
        yara_rule = response.choices[0].message.content.strip()
        print("[INFO] Rule generated successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to generate rule: {str(e)}")
        yara_rule = None

    if not yara_rule:
        raise RuntimeError("AI failed to generate YARA rule")

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".yar")
    tmp_file.write(yara_rule.encode())
    tmp_file.close()
    print(f"[INFO] Rule saved to temporary file: {tmp_file.name}")
    print("[INFO] Generated YARA rule content:\n")
    print(yara_rule)
    return tmp_file.name

@function_tool
def run_yara_ai_scan(sample_path: str):
    results = []

    with trace(workflow_name="yara_ai_scan_workflow"):
        with custom_span(name="generate_rule") as span_rule:
            try:
                rule_file = generate_yara_rule_from_file(sample_path)
                span_rule.span_data.data = {"rule_file": rule_file}
            except Exception as e:
                span_rule.set_error({"message": "Rule generation failed", "data": str(e)})
                print("[ERROR] Rule generation failed.")
                return results

        with custom_span(name="yara_scan") as span_scan:
            try:
                print(f"[INFO] Running YARA scan on {sample_path}")
                completed = subprocess.run(
                    [YARA_EXE, "-s", rule_file, sample_path],
                    capture_output=True,
                    text=True,
                    check=True
                )
                lines = completed.stdout.strip().split("\n")
                if not lines or completed.stdout.strip() == "":
                    print("[INFO] No matches found.")
                else:
                    for line in lines:
                        if line:
                            parts = line.split(" ", 1)
                            rule_name = parts[0]
                            match_detail = parts[1] if len(parts) > 1 else ""
                            results.append({"rule": rule_name, "match": match_detail})
                            print(f"[MATCH] Rule: {rule_name}, Match: {match_detail}")

                span_scan.span_data.data = {"matches": results}

            except subprocess.CalledProcessError as e:
                span_scan.set_error({"message": "YARA scan failed", "data": e.stderr})
                print(f"[ERROR] YARA scan failed: {e.stderr}")

    return results

@function_tool
@contextmanager
def yara_ai_session(sample_path: str):
    try:
        results = run_yara_ai_scan(sample_path)
        yield results
    finally:
        pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: YARA.py <sample_file>")
        sys.exit(1)

    sample_file = sys.argv[1]
    print(f"[INFO] Starting scan for: {sample_file}")

    with yara_ai_session(sample_file) as res:
        if not res:
            print("[INFO] Scan completed. No matches found.")
        else:
            print(f"[INFO] Scan completed. Total matches: {len(res)}")