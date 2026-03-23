import subprocess
import sys
import os
from contextlib import contextmanager

VOLATILITY_EXE = r"C:\Users\Me\volatility3\vol.py"

WINDOWS_PLUGINS = [
    "windows.pslist", "windows.pstree", "windows.dlllist", "windows.cmdline",
    "windows.malfind", "windows.handles", "windows.svcscan",
    "windows.registry.hivelist", "windows.netstat"
]

LINUX_PLUGINS = [
    "linux.pslist", "linux.bash", "linux.lsmod", "linux.lsof", "linux.netstat"
]

def detect_os(memory_path: str) -> str:
    try:
        result = subprocess.run(
            [sys.executable, VOLATILITY_EXE, "-f", memory_path, "linux.pslist"],
            capture_output=True
        )
        stdout = result.stdout.decode(errors="ignore")
        if "PID" in stdout or result.returncode == 0:
            return "linux"
    except Exception:
        pass
    try:
        result = subprocess.run(
            [sys.executable, VOLATILITY_EXE, "-f", memory_path, "windows.pslist"],
            capture_output=True
        )
        stdout = result.stdout.decode(errors="ignore")
        if "Pid" in stdout or result.returncode == 0:
            return "windows"
    except Exception:
        pass
    return "unknown"

def run_volatility_plugin(memory_path: str, plugin_name: str):
    print(f"[INFO] Running plugin: {plugin_name}")
    try:
        completed = subprocess.run(
            [sys.executable, VOLATILITY_EXE, "-f", memory_path, "-r", "csv", plugin_name],
            capture_output=True
        )
        stdout = completed.stdout.decode(errors="replace")
        stderr = completed.stderr.decode(errors="replace")
        output = stdout + stderr
        if not output.strip():
            print(f"[INFO] Plugin {plugin_name} produced no output.")
        return output
    except subprocess.CalledProcessError as e:
        print(f"[WARNING] Plugin {plugin_name} failed: {str(e)}")
        return f"[SKIPPED] {plugin_name} not supported or failed."

def run_volatility(memory_path: str, os_type: str):
    results = {}
    plugins = WINDOWS_PLUGINS if os_type.lower() == "windows" else LINUX_PLUGINS if os_type.lower() == "linux" else []
    if not plugins:
        print("[ERROR] Unknown OS type, skipping scan.")
        return results
    for plugin in plugins:
        results[plugin] = run_volatility_plugin(memory_path, plugin)
    return results

@contextmanager
def volatility_session(memory_path: str, os_type: str):
    results = run_volatility(memory_path, os_type)
    yield results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: VOLATILITY3.py <memory_dump>")
        sys.exit(1)

    memory_file = sys.argv[1]
    os_type = detect_os(memory_file)
    if os_type == "unknown":
        print("[ERROR] Unable to detect OS type from memory dump.")
        sys.exit(1)

    print(f"[INFO] Detected OS: {os_type}")
    print(f"[INFO] Starting Volatility3 scan on {memory_file} for {os_type} OS")

    output_dir = os.path.join(os.path.dirname(memory_file), "Vol3_Output")
    os.makedirs(output_dir, exist_ok=True)

    with volatility_session(memory_file, os_type) as res:
        for plugin, output in res.items():
            print(f"\n===== {plugin} =====\n")
            print(output[:2000])
            with open(os.path.join(output_dir, f"{plugin.replace('.', '_')}.csv"), "w", encoding="utf-8") as f:
                f.write(output)

    print(f"\n[INFO] All results saved in {output_dir}")