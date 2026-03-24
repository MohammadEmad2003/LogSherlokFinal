"""
Office, PDF, and Archive Analysis Tools for CAI Forensic Agent
==============================================================
Tools: oletools, rtfobj, pdfminer, peepdf, floss, py7zr, cabextract
"""
import os
import json
import tempfile
from cai.tools.common import run_command
from cai.sdk.agents import function_tool


# ---------------------------------------------------------------------------
# oletools: Office macro analysis (olevba + mraptor)
# ---------------------------------------------------------------------------
@function_tool
def analyze_office_macros(file_path: str, ctf=None) -> str:
    """
    Extract and analyze VBA macros from Office documents (doc, docx, xls,
    xlsx, ppt, pptx, docm, xlsm). Detects macro malware, suspicious API
    calls, auto-execution triggers, and obfuscated code.

    Args:
        file_path: Path to the Office document
    Returns:
        str: JSON with macro code, suspicious indicators, and risk assessment
    """
    try:
        from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
        from oletools.mraptor import MacroRaptor
    except ImportError:
        return json.dumps({"error": "oletools not installed. Run: pip install oletools"})

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        vba_parser = VBA_Parser(file_path)
        result = {
            "file_path": file_path,
            "file_type": str(vba_parser.type),
            "has_macros": vba_parser.detect_vba_macros(),
        }

        if not result["has_macros"]:
            result["note"] = "No VBA macros detected in this file"
            vba_parser.close()
            return json.dumps(result, indent=2)

        # Extract macros
        macros = []
        for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
            macros.append({
                "filename": filename,
                "stream_path": stream_path,
                "vba_filename": vba_filename,
                "code_length": len(vba_code),
                "code_preview": vba_code[:2000] + ("..." if len(vba_code) > 2000 else ""),
            })
        result["macros"] = macros
        result["total_macros"] = len(macros)

        # Analyze for suspicious indicators
        indicators = []
        for (ioc_type, keyword, description) in vba_parser.analyze_macros():
            indicators.append({
                "type": ioc_type,
                "keyword": keyword,
                "description": description,
            })
        result["indicators"] = indicators[:50]

        # MacroRaptor risk assessment
        all_code = "\n".join(m["code_preview"] for m in macros)
        mraptor = MacroRaptor(all_code)
        mraptor.scan()
        result["mraptor"] = {
            "auto_exec": mraptor.autoexec,
            "writes_file": mraptor.write,
            "executes_command": mraptor.execute,
            "suspicious": mraptor.suspicious,
            "flags": str(mraptor.get_flags()),
        }

        # Risk assessment
        risk_factors = []
        if mraptor.autoexec:
            risk_factors.append("Auto-execution trigger found")
        if mraptor.execute:
            risk_factors.append("Command execution capability")
        if mraptor.write:
            risk_factors.append("File write capability")
        sus_types = {i["type"] for i in indicators}
        if "Suspicious" in sus_types:
            risk_factors.append("Suspicious API calls detected")
        if "AutoExec" in sus_types:
            risk_factors.append("Auto-execution keywords found")

        result["risk_level"] = ("CRITICAL" if len(risk_factors) >= 3
                               else "HIGH" if len(risk_factors) >= 2
                               else "MEDIUM" if risk_factors else "LOW")
        result["risk_factors"] = risk_factors

        vba_parser.close()
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# rtfobj: RTF embedded object extraction
# ---------------------------------------------------------------------------
@function_tool
def extract_rtf_objects(file_path: str, output_dir: str = "/tmp/rtf_objects", ctf=None) -> str:
    """
    Extract embedded objects from RTF files. RTF files with embedded
    OLE objects are commonly used in phishing campaigns and exploit delivery.

    Args:
        file_path: Path to the RTF file
        output_dir: Directory to save extracted objects (default: /tmp/rtf_objects)
    Returns:
        str: JSON with extracted objects, their types, and risk indicators
    """
    try:
        from oletools import rtfobj as rtf_module
    except ImportError:
        return json.dumps({"error": "oletools not installed. Run: pip install oletools"})

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    os.makedirs(output_dir, exist_ok=True)

    try:
        rtf = rtf_module.RtfObjParser(open(file_path, "rb").read())
        rtf.parse()

        objects = []
        for idx, obj in enumerate(rtf.objects):
            obj_info = {
                "index": idx,
                "format_id": obj.format_id,
                "class_name": obj.class_name if hasattr(obj, "class_name") else "unknown",
                "is_ole": obj.is_ole if hasattr(obj, "is_ole") else False,
                "is_package": obj.is_package if hasattr(obj, "is_package") else False,
                "start": obj.start,
                "end": obj.end,
                "size": obj.end - obj.start,
            }

            if hasattr(obj, "olepkgdata") and obj.olepkgdata:
                extract_path = os.path.join(output_dir, f"object_{idx}.bin")
                with open(extract_path, "wb") as out:
                    out.write(obj.olepkgdata)
                obj_info["extracted_to"] = extract_path
                obj_info["extracted_size"] = len(obj.olepkgdata)

            if hasattr(obj, "filename") and obj.filename:
                obj_info["original_filename"] = obj.filename

            objects.append(obj_info)

        result = {
            "file_path": file_path,
            "total_objects": len(objects),
            "objects": objects,
        }

        if objects:
            result["warning"] = "Embedded objects found — analyze each with identify_file_type and scan_yara"
        else:
            result["note"] = "No embedded OLE objects found"

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# pdfminer: PDF text and structure extraction
# ---------------------------------------------------------------------------
@function_tool
def analyze_pdf(file_path: str, extract_text: bool = True, max_pages: int = 20, ctf=None) -> str:
    """
    Analyze a PDF file for forensic indicators. Extracts text content,
    metadata, embedded JavaScript, suspicious streams, form fields,
    and file attachments. Detects common PDF exploit patterns.

    Args:
        file_path: Path to the PDF file
        extract_text: Whether to extract text content (default: True)
        max_pages: Maximum pages to extract text from (default: 20)
    Returns:
        str: JSON with PDF structure, metadata, text, and risk indicators
    """
    try:
        from pdfminer.high_level import extract_text as pdf_extract_text
        from pdfminer.pdfparser import PDFParser
        from pdfminer.pdfdocument import PDFDocument
        from pdfminer.pdfpage import PDFPage
    except ImportError:
        return json.dumps({"error": "pdfminer.six not installed. Run: pip install pdfminer.six"})

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        result = {"file_path": file_path}

        with open(file_path, "rb") as f:
            parser = PDFParser(f)
            doc = PDFDocument(parser)

            # Metadata
            metadata = {}
            if doc.info:
                for info_dict in doc.info:
                    for key, value in info_dict.items():
                        try:
                            if hasattr(value, "decode"):
                                metadata[key] = value.decode("utf-8", errors="replace")
                            else:
                                metadata[key] = str(value)
                        except Exception:
                            metadata[key] = str(value)
            result["metadata"] = metadata

            # Page count
            pages = list(PDFPage.create_pages(doc))
            result["page_count"] = len(pages)

        # Text extraction
        if extract_text:
            try:
                text = pdf_extract_text(file_path, maxpages=max_pages)
                result["text_preview"] = text[:5000] + ("..." if len(text) > 5000 else "")
                result["text_length"] = len(text)
            except Exception as e:
                result["text_error"] = str(e)

        # Scan raw bytes for suspicious content
        with open(file_path, "rb") as f:
            raw = f.read()
            raw_str = raw.decode("latin-1", errors="replace")

        suspicious = []
        if b"/JavaScript" in raw or b"/JS" in raw:
            suspicious.append("Contains JavaScript — potential exploit")
        if b"/OpenAction" in raw or b"/AA" in raw:
            suspicious.append("Auto-action trigger found")
        if b"/Launch" in raw:
            suspicious.append("Launch action — may execute external program")
        if b"/EmbeddedFile" in raw:
            suspicious.append("Contains embedded files")
        if b"/RichMedia" in raw:
            suspicious.append("Contains rich media (Flash/video)")
        if b"/ObjStm" in raw:
            suspicious.append("Object streams found — may hide content")
        if b"eval(" in raw or b"unescape(" in raw:
            suspicious.append("JavaScript eval/unescape — likely obfuscation")
        if b"/Encrypt" in raw:
            suspicious.append("PDF is encrypted")

        result["suspicious_indicators"] = suspicious
        result["risk_level"] = ("HIGH" if len(suspicious) >= 3
                               else "MEDIUM" if suspicious else "LOW")

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# FLOSS: Advanced string extraction (FireEye FLARE)
# ---------------------------------------------------------------------------
@function_tool
def extract_strings_floss(file_path: str, min_length: int = 4,
                          max_strings: int = 200, ctf=None) -> str:
    """
    Extract strings from a binary using FLARE's FLOSS tool. Automatically
    deobfuscates encoded/encrypted strings — far superior to plain 'strings'.
    Falls back to standard strings extraction if FLOSS is not available.

    Args:
        file_path: Path to the binary file
        min_length: Minimum string length to extract (default: 4)
        max_strings: Maximum strings to return (default: 200)
    Returns:
        str: JSON with extracted strings categorized by type (URLs, IPs, paths, etc.)
    """
    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    # Try FLOSS first, fall back to strings
    output = run_command(
        f'floss --minimum-length {min_length} "{file_path}" 2>/dev/null || '
        f'strings -a -n {min_length} "{file_path}"',
        ctf=ctf
    )

    try:
        lines = output.strip().split("\n") if output.strip() else []
        total = len(lines)

        # Categorize strings by forensic relevance
        import re
        urls = []
        ips = []
        file_paths = []
        registries = []
        emails = []
        commands = []
        interesting = []

        url_pattern = re.compile(r'https?://[^\s]+')
        ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        email_pattern = re.compile(r'[\w.-]+@[\w.-]+\.\w+')
        path_pattern = re.compile(r'[A-Z]:\\[^\s]+|/[a-z]+/[^\s]+', re.IGNORECASE)
        reg_pattern = re.compile(r'HKEY_|HKLM|HKCU|SOFTWARE\\|CurrentVersion', re.IGNORECASE)
        cmd_pattern = re.compile(
            r'powershell|cmd\.exe|wscript|cscript|certutil|bitsadmin|'
            r'regsvr32|rundll32|mshta|schtasks|net\s+(user|localgroup)',
            re.IGNORECASE
        )

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if url_pattern.search(line):
                urls.append(line[:200])
            if ip_pattern.search(line):
                ips.append(line[:200])
            if email_pattern.search(line):
                emails.append(line[:200])
            if path_pattern.search(line):
                file_paths.append(line[:200])
            if reg_pattern.search(line):
                registries.append(line[:200])
            if cmd_pattern.search(line):
                commands.append(line[:200])

        result = {
            "file_path": file_path,
            "total_strings": total,
            "showing": min(total, max_strings),
            "categorized": {
                "urls": urls[:30],
                "ip_addresses": list(set(ips))[:30],
                "email_addresses": list(set(emails))[:20],
                "file_paths": file_paths[:30],
                "registry_keys": registries[:20],
                "suspicious_commands": commands[:20],
            },
            "all_strings_preview": lines[:max_strings],
        }

        if commands:
            result["warning"] = f"Found {len(commands)} suspicious command references"

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "raw_output": output[:3000]})


# ---------------------------------------------------------------------------
# py7zr / cabextract: Archive extraction
# ---------------------------------------------------------------------------
@function_tool
def extract_archive(file_path: str, output_dir: str = "/tmp/extracted",
                    password: str = "", ctf=None) -> str:
    """
    Extract contents of archive files (7z, zip, cab, tar, gz, rar).
    Malware droppers commonly use archives to bypass email filters.
    Supports password-protected archives.

    Args:
        file_path: Path to the archive file
        output_dir: Directory to extract into (default: /tmp/extracted)
        password: Password for encrypted archives (default: empty)
    Returns:
        str: JSON with extracted file listing, sizes, and types
    """
    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    os.makedirs(output_dir, exist_ok=True)
    ext = os.path.splitext(file_path)[1].lower()

    try:
        # 7z archives
        if ext in [".7z"]:
            try:
                import py7zr
                with py7zr.SevenZipFile(file_path, mode="r",
                                         password=password or None) as z:
                    z.extractall(path=output_dir)
                    names = z.getnames()
            except ImportError:
                return json.dumps({"error": "py7zr not installed. Run: pip install py7zr"})

        # ZIP archives
        elif ext in [".zip"]:
            import zipfile
            with zipfile.ZipFile(file_path, "r") as z:
                if password:
                    z.setpassword(password.encode())
                z.extractall(output_dir)
                names = z.namelist()

        # CAB archives
        elif ext in [".cab"]:
            result = run_command(f'cabextract -d "{output_dir}" "{file_path}"', ctf=ctf)
            names = [f for f in os.listdir(output_dir) if os.path.isfile(os.path.join(output_dir, f))]

        # TAR/GZ archives
        elif ext in [".tar", ".gz", ".tgz", ".tar.gz", ".bz2", ".xz"]:
            import tarfile
            with tarfile.open(file_path, "r:*") as t:
                t.extractall(output_dir, filter="data")
                names = t.getnames()

        # RAR archives
        elif ext in [".rar"]:
            result = run_command(f'unrar x -o+ -p{password or "-"} "{file_path}" "{output_dir}/"', ctf=ctf)
            names = [f for f in os.listdir(output_dir) if os.path.isfile(os.path.join(output_dir, f))]

        else:
            # Fallback to 7z CLI which handles most formats
            cmd = f'7z x -o"{output_dir}" '
            if password:
                cmd += f'-p"{password}" '
            cmd += f'"{file_path}"'
            run_command(cmd, ctf=ctf)
            names = []
            for root, dirs, files in os.walk(output_dir):
                for fname in files:
                    names.append(os.path.relpath(os.path.join(root, fname), output_dir))

        # Build file listing with sizes
        files_info = []
        for name in names[:100]:
            full_path = os.path.join(output_dir, name)
            if os.path.isfile(full_path):
                files_info.append({
                    "name": name,
                    "size": os.path.getsize(full_path),
                    "path": full_path,
                })

        return json.dumps({
            "archive": file_path,
            "output_dir": output_dir,
            "total_files": len(names),
            "files": files_info,
            "note": "Run identify_file_type on each extracted file for analysis routing"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})
