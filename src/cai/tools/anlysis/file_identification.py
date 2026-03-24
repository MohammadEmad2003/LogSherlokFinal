"""
File Type & Metadata Identification Tools for CAI Forensic Agent
================================================================
Tools: python-magic, exifread, pefile, pyelftools, ssdeep/tlsh
"""
import os
import json
import hashlib
from cai.tools.common import run_command
from cai.sdk.agents import function_tool

@function_tool
def identify_file_type(file_path: str, ctf=None) -> str:
    """
    Detect the true file type of a file using magic bytes (libmagic).
    This overrides file extensions and is the first step in deciding
    which analysis tool to call next.

    Args:
        file_path: Path to the file to identify
    Returns:
        str: JSON with mime_type, description, and file metadata
    """
    try:
        import magic
    except ImportError:
        return json.dumps({"error": "python-magic not installed. Run: pip install python-magic"})

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        mime = magic.Magic(mime=True)
        detailed = magic.Magic(mime=False)

        mime_type = mime.from_file(file_path)
        description = detailed.from_file(file_path)
        file_size = os.path.getsize(file_path)
        extension = os.path.splitext(file_path)[1].lower()

        # Compute hashes for chain of custody
        with open(file_path, "rb") as f:
            data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()

        # Classify for downstream tool routing
        category = _classify_file(mime_type, extension)

        return json.dumps({
            "file_path": file_path,
            "mime_type": mime_type,
            "description": description,
            "extension": extension,
            "size_bytes": file_size,
            "sha256": sha256,
            "md5": md5,
            "category": category,
            "suggested_tools": _suggest_tools(category)
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


def _classify_file(mime_type: str, extension: str) -> str:
    """Classify file into forensic analysis categories."""
    mime_lower = mime_type.lower()
    if "elf" in mime_lower or "x-sharedlib" in mime_lower:
        return "linux_elf"
    elif "x-dosexec" in mime_lower or "portable-executable" in mime_lower:
        return "windows_pe"
    elif "x-executable" in mime_lower:
        # Check extension to disambiguate
        if extension in [".exe", ".dll", ".sys", ".scr", ".cpl"]:
            return "windows_pe"
        return "linux_elf"
    elif "pdf" in mime_lower:
        return "pdf"
    elif any(x in mime_lower for x in ["msword", "officedocument", "ms-excel", "ms-powerpoint"]):
        return "office_document"
    elif "rtf" in mime_lower:
        return "rtf"
    elif any(x in mime_lower for x in ["zip", "x-7z", "x-rar", "x-tar", "gzip", "x-cab"]):
        return "archive"
    elif any(x in mime_lower for x in ["image/", "jpeg", "png", "gif", "tiff", "bmp"]):
        return "image"
    elif "evtx" in extension or "evt" in extension:
        return "windows_eventlog"
    elif any(x in mime_lower for x in ["pcap", "vnd.tcpdump"]):
        return "network_capture"
    elif "text" in mime_lower or "json" in mime_lower or "xml" in mime_lower:
        return "text_log"
    elif any(x in extension for x in [".dmp", ".raw", ".mem", ".vmem", ".lime"]):
        return "memory_dump"
    elif any(x in extension for x in [".e01", ".dd", ".img", ".vmdk", ".vhd", ".qcow2"]):
        return "disk_image"
    else:
        return "unknown"


def _suggest_tools(category: str) -> list:
    """Suggest appropriate forensic tools based on file category."""
    suggestions = {
        "windows_pe": ["analyze_pe", "scan_yara", "extract_strings_floss", "compute_fuzzy_hash"],
        "linux_elf": ["analyze_elf", "scan_yara", "extract_strings_floss", "compute_fuzzy_hash"],
        "pdf": ["analyze_pdf", "scan_yara"],
        "office_document": ["analyze_office_macros", "scan_yara"],
        "rtf": ["extract_rtf_objects", "scan_yara"],
        "archive": ["extract_archive"],
        "image": ["extract_exif_metadata"],
        "windows_eventlog": ["parse_evtx", "run_hayabusa", "run_chainsaw"],
        "network_capture": ["analyze_pcap"],
        "text_log": ["parse_apache_log", "parse_auditd"],
        "memory_dump": ["volatility_analyze"],
        "disk_image": ["list_partitions", "generate_timeline"],
    }
    return suggestions.get(category, ["identify_file_type", "extract_strings_floss"])


# ---------------------------------------------------------------------------
# exifread: EXIF metadata extraction
# ---------------------------------------------------------------------------
@function_tool
def extract_exif_metadata(file_path: str, ctf=None) -> str:
    """
    Extract EXIF metadata from images, PDFs, and Office files.
    Reveals creation dates, GPS coordinates, author names, camera info,
    and software used — valuable for attribution and timeline building.

    Args:
        file_path: Path to the file to extract EXIF data from
    Returns:
        str: JSON with all extracted EXIF tags
    """
    try:
        import exifread
    except ImportError:
        return json.dumps({"error": "exifread not installed. Run: pip install exifread"})

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        with open(file_path, "rb") as f:
            tags = exifread.process_file(f, details=True)

        if not tags:
            return json.dumps({"file_path": file_path, "metadata": {},
                              "note": "No EXIF metadata found in this file"})

        metadata = {}
        gps_data = {}
        for tag_name, tag_value in tags.items():
            tag_str = str(tag_value)
            metadata[tag_name] = tag_str
            if "GPS" in tag_name:
                gps_data[tag_name] = tag_str

        result = {
            "file_path": file_path,
            "total_tags": len(metadata),
            "metadata": metadata,
        }
        if gps_data:
            result["gps_data"] = gps_data
            result["warning"] = "GPS coordinates found — potential geolocation data"

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})



@function_tool
def analyze_pe(file_path: str, ctf=None) -> str:
    """
    Analyze a Windows PE (EXE/DLL) file. Extracts imports, exports,
    sections, timestamps, compile time, imphash, and suspicious indicators.
    Core tool for malware triage.

    Args:
        file_path: Path to the PE file to analyze
    Returns:
        str: JSON with PE structure, imports, exports, sections, and anomalies
    """
    try:
        import pefile
    except ImportError:
        return json.dumps({"error": "pefile not installed. Run: pip install pefile"})

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        pe = pefile.PE(file_path)
        result = {
            "file_path": file_path,
            "machine": hex(pe.FILE_HEADER.Machine),
            "compile_time": pe.FILE_HEADER.TimeDateStamp,
            "compile_time_utc": str(pe.FILE_HEADER.TimeDateStamp),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "imphash": pe.get_imphash() if hasattr(pe, "get_imphash") else "N/A",
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "is_dll": pe.is_dll(),
            "is_exe": pe.is_exe(),
            "is_driver": pe.is_driver(),
        }

        # Sections
        sections = []
        for section in pe.sections:
            sec_name = section.Name.decode("utf-8", errors="replace").strip("\x00")
            entropy = section.get_entropy()
            sections.append({
                "name": sec_name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 2),
                "suspicious": entropy > 7.0  # High entropy = packed/encrypted
            })
        result["sections"] = sections

        # Imports (top 50)
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:20]:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                funcs = [imp.name.decode("utf-8", errors="replace")
                         for imp in entry.imports[:10] if imp.name]
                imports.append({"dll": dll_name, "functions": funcs,
                               "total_functions": len(entry.imports)})
        result["imports"] = imports
        result["total_import_dlls"] = len(imports)

        # Exports
        exports = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:30]:
                name = exp.name.decode("utf-8", errors="replace") if exp.name else f"ord_{exp.ordinal}"
                exports.append({"name": name, "ordinal": exp.ordinal})
        result["exports"] = exports

        # Suspicious indicators
        anomalies = []
        suspicious_imports = [
            "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
            "CreateRemoteThread", "NtUnmapViewOfSection", "IsDebuggerPresent",
            "GetProcAddress", "LoadLibraryA", "URLDownloadToFile",
            "WinExec", "ShellExecute", "InternetOpen"
        ]
        found_suspicious = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode("utf-8", errors="replace") in suspicious_imports:
                        found_suspicious.append(imp.name.decode("utf-8", errors="replace"))
        if found_suspicious:
            anomalies.append(f"Suspicious imports: {', '.join(found_suspicious)}")

        high_entropy_sections = [s["name"] for s in sections if s["suspicious"]]
        if high_entropy_sections:
            anomalies.append(f"High entropy sections (packed/encrypted?): {', '.join(high_entropy_sections)}")

        warnings = pe.get_warnings()
        if warnings:
            anomalies.extend(warnings[:5])

        result["anomalies"] = anomalies
        result["risk_level"] = "HIGH" if len(anomalies) >= 2 else "MEDIUM" if anomalies else "LOW"

        pe.close()
        return json.dumps(result, indent=2, default=str)
    except pefile.PEFormatError as e:
        return json.dumps({"error": f"Not a valid PE file: {e}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# pyelftools: Linux ELF binary analysis
# ---------------------------------------------------------------------------
@function_tool
def analyze_elf(file_path: str, ctf=None) -> str:
    """
    Analyze a Linux ELF binary. Parses headers, sections, symbols,
    and dynamic linking information. The Linux equivalent of analyze_pe.

    Args:
        file_path: Path to the ELF binary to analyze
    Returns:
        str: JSON with ELF structure, sections, symbols, and dynamic info
    """
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        return json.dumps({"error": "pyelftools not installed. Run: pip install pyelftools"})

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)

            result = {
                "file_path": file_path,
                "arch": elf.get_machine_arch(),
                "elf_class": elf.elfclass,
                "endianness": "little" if elf.little_endian else "big",
                "elf_type": elf.header.e_type,
                "entry_point": hex(elf.header.e_entry),
                "num_sections": elf.num_sections(),
                "num_segments": elf.num_segments(),
            }

            # Sections
            sections = []
            for section in elf.iter_sections():
                sections.append({
                    "name": section.name,
                    "type": section["sh_type"],
                    "size": section["sh_size"],
                    "flags": section["sh_flags"],
                })
            result["sections"] = sections[:30]

            # Symbols (from .symtab and .dynsym)
            symbols = []
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        if symbol.name:
                            symbols.append({
                                "name": symbol.name,
                                "type": symbol["st_info"]["type"],
                                "bind": symbol["st_info"]["bind"],
                                "section_index": symbol["st_shndx"],
                            })
            result["symbols"] = symbols[:50]
            result["total_symbols"] = len(symbols)

            # Dynamic section (shared libraries)
            dynamic_libs = []
            for segment in elf.iter_segments():
                if segment.header.p_type == "PT_DYNAMIC":
                    for tag in segment.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            dynamic_libs.append(tag.needed)
            result["dynamic_libraries"] = dynamic_libs

            # Suspicious indicators
            anomalies = []
            suspicious_funcs = ["execve", "system", "popen", "dlopen",
                              "ptrace", "mprotect", "mmap"]
            found = [s["name"] for s in symbols if s["name"] in suspicious_funcs]
            if found:
                anomalies.append(f"Suspicious functions: {', '.join(found)}")
            if not dynamic_libs:
                anomalies.append("Statically linked — may be intentionally self-contained")
            result["anomalies"] = anomalies

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# ssdeep / tlsh: Fuzzy hashing
# ---------------------------------------------------------------------------
@function_tool
def compute_fuzzy_hash(file_path: str, algorithm: str = "ssdeep", ctf=None) -> str:
    """
    Compute fuzzy hash of a file to find similar files (e.g., malware variants).
    ssdeep is best for general use; tlsh is better for large files.

    Args:
        file_path: Path to the file to hash
        algorithm: 'ssdeep' or 'tlsh' (default: ssdeep)
    Returns:
        str: JSON with fuzzy hash value and standard hashes
    """
    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    result = {"file_path": file_path, "algorithm": algorithm}

    # Standard hashes for reference
    with open(file_path, "rb") as f:
        data = f.read()
        result["sha256"] = hashlib.sha256(data).hexdigest()
        result["md5"] = hashlib.md5(data).hexdigest()
        result["size_bytes"] = len(data)

    try:
        if algorithm == "ssdeep":
            import ssdeep
            result["fuzzy_hash"] = ssdeep.hash_from_file(file_path)
        elif algorithm == "tlsh":
            import tlsh
            result["fuzzy_hash"] = tlsh.hash(data)
        else:
            return json.dumps({"error": f"Unknown algorithm: {algorithm}. Use 'ssdeep' or 'tlsh'"})

        return json.dumps(result, indent=2)
    except ImportError:
        return json.dumps({"error": f"{algorithm} not installed. Run: pip install {algorithm}"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@function_tool
def compare_fuzzy_hashes(hash1: str, hash2: str, algorithm: str = "ssdeep", ctf=None) -> str:
    """
    Compare two fuzzy hashes to determine file similarity.
    Score of 0 = no match, 100 = identical (ssdeep).
    For tlsh: 0 = identical, higher = more different.

    Args:
        hash1: First fuzzy hash
        hash2: Second fuzzy hash
        algorithm: 'ssdeep' or 'tlsh'
    Returns:
        str: JSON with similarity score and interpretation
    """
    try:
        if algorithm == "ssdeep":
            import ssdeep
            score = ssdeep.compare(hash1, hash2)
            interpretation = ("identical" if score == 100 else "very similar" if score > 70
                            else "somewhat similar" if score > 30 else "different")
        elif algorithm == "tlsh":
            import tlsh
            score = tlsh.diff(hash1, hash2)
            interpretation = ("identical" if score == 0 else "very similar" if score < 30
                            else "somewhat similar" if score < 100 else "different")
        else:
            return json.dumps({"error": f"Unknown algorithm: {algorithm}"})

        return json.dumps({
            "algorithm": algorithm,
            "score": score,
            "interpretation": interpretation
        }, indent=2)
    except ImportError:
        return json.dumps({"error": f"{algorithm} not installed. Run: pip install {algorithm}"})
    except Exception as e:
        return json.dumps({"error": str(e)})
