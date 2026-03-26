import os
import sys
import json
import tempfile
import shutil
import subprocess
import urllib.request
import zipfile
from contextlib import contextmanager

# مسار fls.exe من Sleuth Kit
DEFAULT_SLEUTHKIT_BIN = r"C:\Users\WinLab\Desktop\sleuthkit-4.14.0-win32\bin"
SLEUTHKIT_VERSION = "4.14.0"
SLEUTHKIT_ARCHIVE_NAME = f"sleuthkit-{SLEUTHKIT_VERSION}-win32.zip"
SLEUTHKIT_DOWNLOAD_URL = f"https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-{SLEUTHKIT_VERSION}/{SLEUTHKIT_ARCHIVE_NAME}"
MANAGED_SLEUTHKIT_HOME = os.path.join(
    os.environ.get("LOCALAPPDATA", tempfile.gettempdir()),
    "LogSherlock"
)
MANAGED_SLEUTHKIT_ROOT = os.path.join(MANAGED_SLEUTHKIT_HOME, f"sleuthkit-{SLEUTHKIT_VERSION}-win32")
MANAGED_SLEUTHKIT_BIN = os.path.join(MANAGED_SLEUTHKIT_ROOT, "bin")
SLEUTHKIT_AUTO_DOWNLOAD_ATTEMPTED = False

def get_sleuthkit_candidate_dirs():
    candidate_dirs = []
    env_bin_dir = os.environ.get("SLEUTHKIT_BIN") or os.environ.get("FORENSICS_SLEUTHKIT_BIN")
    env_home_dir = os.environ.get("SLEUTHKIT_HOME") or os.environ.get("FORENSICS_SLEUTHKIT_HOME")

    if env_bin_dir:
        candidate_dirs.append(env_bin_dir)
    if env_home_dir:
        candidate_dirs.append(os.path.join(env_home_dir, "bin"))

    candidate_dirs.append(MANAGED_SLEUTHKIT_BIN)
    candidate_dirs.append(DEFAULT_SLEUTHKIT_BIN)

    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        candidate_dirs.extend([
            os.path.join(user_profile, "Desktop", "sleuthkit", "bin"),
            os.path.join(user_profile, "Desktop", "sleuthkit-4.14.0-win32", "bin"),
            os.path.join(user_profile, "Downloads", "sleuthkit-4.14.0-win32", "bin")
        ])

    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidate_dirs.append(os.path.join(program_files, "sleuthkit", "bin"))

    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if program_files_x86:
        candidate_dirs.append(os.path.join(program_files_x86, "sleuthkit", "bin"))

    unique_dirs = []
    for candidate_dir in candidate_dirs:
        if not candidate_dir:
            continue

        normalized_dir = os.path.normpath(candidate_dir)
        if normalized_dir not in unique_dirs:
            unique_dirs.append(normalized_dir)

    return unique_dirs

def ensure_sleuthkit_installed():
    global SLEUTHKIT_AUTO_DOWNLOAD_ATTEMPTED

    if SLEUTHKIT_AUTO_DOWNLOAD_ATTEMPTED:
        return os.path.isdir(MANAGED_SLEUTHKIT_BIN)

    SLEUTHKIT_AUTO_DOWNLOAD_ATTEMPTED = True
    os.makedirs(MANAGED_SLEUTHKIT_HOME, exist_ok=True)

    archive_path = os.path.join(MANAGED_SLEUTHKIT_HOME, SLEUTHKIT_ARCHIVE_NAME)
    fls_path = os.path.join(MANAGED_SLEUTHKIT_BIN, "fls.exe")
    tsk_recover_path = os.path.join(MANAGED_SLEUTHKIT_BIN, "tsk_recover.exe")
    mactime_path = os.path.join(MANAGED_SLEUTHKIT_BIN, "mactime.exe")

    if os.path.exists(fls_path) and os.path.exists(tsk_recover_path) and os.path.exists(mactime_path):
        return True

    try:
        if not os.path.exists(archive_path):
            print(f"[INFO] Downloading Sleuth Kit from {SLEUTHKIT_DOWNLOAD_URL}")
            urllib.request.urlretrieve(SLEUTHKIT_DOWNLOAD_URL, archive_path)

        print(f"[INFO] Extracting Sleuth Kit to {MANAGED_SLEUTHKIT_HOME}")
        with zipfile.ZipFile(archive_path, "r") as zip_file:
            zip_file.extractall(MANAGED_SLEUTHKIT_HOME)
    except Exception as exc:
        print(f"[WARNING] Could not set up Sleuth Kit automatically: {exc}")
        return False

    return os.path.exists(fls_path)

def resolve_sleuthkit_tool(tool_name):
    path_match = shutil.which(tool_name)
    if path_match:
        return path_match, []

    searched_paths = []
    for candidate_dir in get_sleuthkit_candidate_dirs():
        candidate_path = os.path.join(candidate_dir, tool_name)
        searched_paths.append(candidate_path)
        if os.path.exists(candidate_path):
            return candidate_path, searched_paths

    if ensure_sleuthkit_installed():
        candidate_path = os.path.join(MANAGED_SLEUTHKIT_BIN, tool_name)
        searched_paths.append(candidate_path)
        if os.path.exists(candidate_path):
            return candidate_path, searched_paths

    return None, searched_paths

def get_fls_exe():
    return resolve_sleuthkit_tool("fls.exe")

def get_tsk_recover_exe():
    return resolve_sleuthkit_tool("tsk_recover.exe")

def get_mactime_exe():
    return resolve_sleuthkit_tool("mactime.exe")

def build_missing_tool_message(tool_name, searched_paths):
    message = [
        f"{tool_name} not found.",
        "Set SLEUTHKIT_BIN to your Sleuth Kit bin folder or add it to PATH."
    ]
    if searched_paths:
        message.append("Searched: " + "; ".join(searched_paths))
    return " ".join(message)

def function_tool(func):
    def wrapper(*args, **kwargs):
        print(f"[TOOL] Running {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

@contextmanager
def forensic_session(image_path):
    os_type = detect_os(image_path)
    print(f"[INFO] Detected OS: {os_type}")
    try:
        yield os_type
    finally:
        print("[INFO] Forensic session ended.")

def detect_os(image_path):
    # نفترض Windows بشكل افتراضي
    return 'windows'

def count_recovered_files(recovery_dir):
    recovered_count = 0
    for _, _, files in os.walk(recovery_dir):
        recovered_count += len(files)
    return recovered_count

def count_deleted_file_entries(listing_path):
    deleted_file_count = 0
    try:
        with open(listing_path, "r", encoding="utf-8", errors="ignore") as listing_file:
            for line in listing_file:
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                entry_type = stripped_line.split(None, 1)[0]
                if entry_type.startswith("r/"):
                    deleted_file_count += 1
    except OSError as exc:
        print(f"[ERROR] Failed to count deleted file entries: {exc}")
        return 0

    return deleted_file_count

@function_tool
def run_tsk_mft(image_path, output_dir):
    fls_exe, searched_paths = get_fls_exe()
    if not fls_exe:
        print(f"[ERROR] {build_missing_tool_message('fls.exe', searched_paths)}")
        return None

    bodyfile_path = os.path.join(output_dir, "bodyfile.txt")
    fls_cmd = [
        fls_exe,
        "-r",
        "-m",
        "/",
        image_path
    ]
    try:
        with open(bodyfile_path, "w", encoding="utf-8") as f:
            subprocess.run(fls_cmd, stdout=f, check=False)
        return bodyfile_path if os.path.exists(bodyfile_path) else None
    except Exception as e:
        print(f"[ERROR] {e}")
        return None

@function_tool
def run_plaso(image_path, output_dir):
    bodyfile_path = os.path.join(output_dir, "bodyfile.txt")
    csv_file = os.path.join(output_dir, "timeline.csv")

    try:
        import plaso
    except ImportError:
        mactime_exe, searched_paths = get_mactime_exe()
        if not mactime_exe:
            print(f"[WARNING] Plaso not installed and mactime.exe unavailable. {build_missing_tool_message('mactime.exe', searched_paths)}")
            return None
        if not os.path.exists(bodyfile_path):
            print("[WARNING] Plaso not installed and bodyfile.txt is missing, skipping timeline generation.")
            return None

        cmd_mactime = [
            mactime_exe,
            "-b",
            bodyfile_path,
            "-d"
        ]

        try:
            with open(csv_file, "w", encoding="utf-8") as timeline_file:
                completed_process = subprocess.run(
                    cmd_mactime,
                    stdout=timeline_file,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False
                )
        except OSError as exc:
            print(f"[ERROR] Failed to generate timeline with mactime: {exc}")
            return None

        if completed_process.returncode != 0:
            error_message = completed_process.stderr.strip() or "mactime exited with a non-zero status"
            print(f"[ERROR] Failed to generate timeline with mactime: {error_message}")
            return None

        return csv_file if os.path.exists(csv_file) else None

    plaso_file = os.path.join(output_dir, "timeline.plaso")

    if os.path.exists(csv_file):
        os.remove(csv_file)

    cmd_log2timeline = [
        sys.executable, "-m", "plaso.scripts.log2timeline",
        "--storage_file", plaso_file,
        image_path
    ]
    subprocess.run(cmd_log2timeline, check=False)

    cmd_psort = [
        sys.executable, "-m", "plaso.scripts.psort",
        "-o", "dynamic",
        "-w", csv_file,
        plaso_file
    ]
    subprocess.run(cmd_psort, check=False)

    return csv_file if os.path.exists(csv_file) else None

@function_tool
def analyze_deleted_files(image_path, output_dir):
    fls_exe, searched_paths = get_fls_exe()
    if not fls_exe:
        error_message = build_missing_tool_message("fls.exe", searched_paths)
        print(f"[ERROR] {error_message}")
        return {
            "count": 0,
            "listing_path": None,
            "error": error_message
        }

    deleted_listing_path = os.path.join(output_dir, "deleted_files.txt")
    fls_deleted_cmd = [
        fls_exe,
        "-r",
        "-d",
        image_path
    ]

    try:
        with open(deleted_listing_path, "w", encoding="utf-8") as listing_file:
            completed_process = subprocess.run(
                fls_deleted_cmd,
                stdout=listing_file,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
    except OSError as exc:
        print(f"[ERROR] Failed to list deleted files: {exc}")
        return {
            "count": 0,
            "listing_path": None,
            "error": str(exc)
        }

    if completed_process.returncode != 0:
        error_message = completed_process.stderr.strip() or "fls exited with a non-zero status"
        print(f"[ERROR] Failed to list deleted files: {error_message}")
        return {
            "count": 0,
            "listing_path": deleted_listing_path if os.path.exists(deleted_listing_path) else None,
            "error": error_message
        }

    deleted_file_count = count_deleted_file_entries(deleted_listing_path)
    print(f"[INFO] Deleted files listed: {deleted_file_count}")
    return {
        "count": deleted_file_count,
        "listing_path": deleted_listing_path,
        "error": None
    }

@function_tool
def recover_deleted_files(image_path, output_dir):
    tsk_recover_exe, searched_paths = get_tsk_recover_exe()
    if not tsk_recover_exe:
        error_message = build_missing_tool_message("tsk_recover.exe", searched_paths)
        print(f"[ERROR] {error_message}")
        return {
            "recovered_count": 0,
            "recovery_dir": None,
            "error": error_message
        }

    recovery_dir = os.path.join(output_dir, "Recovered_Deleted_Files")
    os.makedirs(recovery_dir, exist_ok=True)

    tsk_recover_cmd = [
        tsk_recover_exe,
        image_path,
        recovery_dir
    ]

    try:
        completed_process = subprocess.run(
            tsk_recover_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
    except OSError as exc:
        print(f"[ERROR] Failed to recover deleted files: {exc}")
        return {
            "recovered_count": 0,
            "recovery_dir": recovery_dir,
            "error": str(exc)
        }

    if completed_process.returncode != 0:
        error_message = completed_process.stderr.strip() or completed_process.stdout.strip() or "tsk_recover exited with a non-zero status"
        print(f"[ERROR] Failed to recover deleted files: {error_message}")
        return {
            "recovered_count": 0,
            "recovery_dir": recovery_dir,
            "error": error_message
        }

    recovered_count = count_recovered_files(recovery_dir)
    print(f"[INFO] Recovered deleted files: {recovered_count}")
    return {
        "recovered_count": recovered_count,
        "recovery_dir": recovery_dir,
        "error": None
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python DISC.py <disk_image>")
        sys.exit(1)

    image_file = sys.argv[1]
    output_dir = os.path.join(os.path.dirname(image_file), "Forensics_Output")
    os.makedirs(output_dir, exist_ok=True)

    with forensic_session(image_file) as os_type:
        results = {}

        if os_type == "windows":
            results["MFT_Bodyfile"] = run_tsk_mft(image_file, output_dir)
            results["Deleted_Files"] = analyze_deleted_files(image_file, output_dir)
            results["Recovered_Deleted_Files"] = recover_deleted_files(image_file, output_dir)
        else:
            print("[INFO] Skipping MFT analysis (non-Windows)")

        csv_path = run_plaso(image_file, output_dir)
        results["Timeline_CSV"] = csv_path is not None
        if csv_path:
            print(f"[INFO] Timeline CSV generated: {csv_path}")

    summary_file = os.path.join(output_dir, "summary_results.json")
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("[SUMMARY]")
    print(json.dumps(results, indent=2))
    print(f"[DONE] Output in: {output_dir}")

if __name__ == "__main__":
    main()