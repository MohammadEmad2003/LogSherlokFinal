"""
Advanced Binary Analysis & Reverse Engineering Tools for CAI Forensic Agent
===========================================================================
Tools: capstone, unicorn-engine, angr, frida, FindAES
"""
import os
import json
import hashlib
from cai.tools.common import run_command
from cai.sdk.agents import function_tool


# ---------------------------------------------------------------------------
# Capstone: Disassembly — raw bytes to assembly instructions
# ---------------------------------------------------------------------------
@function_tool
def disassemble_bytes(hex_bytes: str = "", file_path: str = "",
                      offset: int = 0, length: int = 256,
                      arch: str = "x86_64", ctf=None) -> str:
    """
    Disassemble raw bytes or file content into assembly instructions using
    Capstone. Great for detecting shellcode in memory dumps or PE sections.

    Args:
        hex_bytes: Hex string of bytes to disassemble (e.g., '90909090eb05')
        file_path: Alternatively, path to binary file to disassemble from
        offset: Byte offset to start disassembly (used with file_path)
        length: Number of bytes to disassemble (default: 256)
        arch: Architecture: 'x86', 'x86_64', 'arm', 'arm64', 'mips' (default: x86_64)
    Returns:
        str: JSON with disassembled instructions and shellcode indicators
    """
    try:
        from capstone import (Cs, CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64,
                             CS_ARCH_MIPS, CS_MODE_32, CS_MODE_64, CS_MODE_ARM,
                             CS_MODE_MIPS32)
    except ImportError:
        return json.dumps({"error": "capstone not installed. Run: pip install capstone"})

    arch_map = {
        "x86":    (CS_ARCH_X86, CS_MODE_32),
        "x86_64": (CS_ARCH_X86, CS_MODE_64),
        "arm":    (CS_ARCH_ARM, CS_MODE_ARM),
        "arm64":  (CS_ARCH_ARM64, CS_MODE_ARM),
        "mips":   (CS_ARCH_MIPS, CS_MODE_MIPS32),
    }

    if arch not in arch_map:
        return json.dumps({"error": f"Unknown arch: {arch}. Choose: {list(arch_map.keys())}"})

    try:
        # Get bytes to disassemble
        if hex_bytes:
            code = bytes.fromhex(hex_bytes.replace(" ", "").replace("\\x", ""))
        elif file_path:
            if not os.path.isfile(file_path):
                return json.dumps({"error": f"File not found: {file_path}"})
            with open(file_path, "rb") as f:
                f.seek(offset)
                code = f.read(length)
        else:
            return json.dumps({"error": "Provide either hex_bytes or file_path"})

        cs_arch, cs_mode = arch_map[arch]
        md = Cs(cs_arch, cs_mode)
        md.detail = True

        instructions = []
        for insn in md.disasm(code, offset):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "operands": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size,
            })

        # Shellcode detection heuristics
        shellcode_indicators = []
        mnemonics = [i["mnemonic"] for i in instructions]
        if "int" in mnemonics:
            shellcode_indicators.append("INT instruction found (syscall/interrupt)")
        if "syscall" in mnemonics:
            shellcode_indicators.append("SYSCALL instruction (Linux syscall)")
        if any(m.startswith("call") for m in mnemonics):
            call_count = sum(1 for m in mnemonics if m.startswith("call"))
            shellcode_indicators.append(f"{call_count} CALL instructions")
        if instructions and instructions[0]["mnemonic"] == "nop":
            nop_count = sum(1 for i in instructions if i["mnemonic"] == "nop")
            if nop_count > 3:
                shellcode_indicators.append(f"NOP sled detected ({nop_count} NOPs)")

        # Check for common shellcode patterns
        hex_code = code.hex()
        if "6a" in hex_code[:20]:
            shellcode_indicators.append("Stack push operations near start (typical shellcode)")

        result = {
            "arch": arch,
            "total_bytes": len(code),
            "total_instructions": len(instructions),
            "instructions": instructions[:100],
            "shellcode_indicators": shellcode_indicators,
        }

        if shellcode_indicators:
            result["warning"] = "Potential shellcode detected"

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Unicorn Engine: CPU emulation — safely execute shellcode
# ---------------------------------------------------------------------------
@function_tool
def emulate_shellcode(hex_bytes: str, arch: str = "x86_64",
                      max_instructions: int = 500, ctf=None) -> str:
    """
    Safely emulate shellcode in an isolated CPU emulator (Unicorn Engine).
    Observes behavior (syscalls, memory access, register state) without
    risking the host machine.

    Args:
        hex_bytes: Hex string of shellcode bytes to emulate
        arch: Architecture: 'x86', 'x86_64' (default: x86_64)
        max_instructions: Maximum instructions to emulate before stopping (default: 500)
    Returns:
        str: JSON with execution trace, register state, and behavioral observations
    """
    try:
        from unicorn import (Uc, UC_ARCH_X86, UC_MODE_32, UC_MODE_64,
                            UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_MEM_WRITE,
                            UC_HOOK_INTR, UC_ERR_OK)
        from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX,
                                       UC_X86_REG_ECX, UC_X86_REG_EDX,
                                       UC_X86_REG_ESP, UC_X86_REG_EIP,
                                       UC_X86_REG_RAX, UC_X86_REG_RBX,
                                       UC_X86_REG_RCX, UC_X86_REG_RDX,
                                       UC_X86_REG_RSP, UC_X86_REG_RIP)
    except ImportError:
        return json.dumps({"error": "unicorn-engine not installed. Run: pip install unicorn"})

    try:
        code = bytes.fromhex(hex_bytes.replace(" ", "").replace("\\x", ""))
    except ValueError as e:
        return json.dumps({"error": f"Invalid hex: {e}"})

    try:
        BASE_ADDR = 0x400000
        STACK_ADDR = 0x7FF000
        STACK_SIZE = 0x10000

        if arch == "x86":
            uc = Uc(UC_ARCH_X86, UC_MODE_32)
            reg_map = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX,
                       "ecx": UC_X86_REG_ECX, "edx": UC_X86_REG_EDX,
                       "esp": UC_X86_REG_ESP, "eip": UC_X86_REG_EIP}
        elif arch == "x86_64":
            uc = Uc(UC_ARCH_X86, UC_MODE_64)
            reg_map = {"rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX,
                       "rcx": UC_X86_REG_RCX, "rdx": UC_X86_REG_RDX,
                       "rsp": UC_X86_REG_RSP, "rip": UC_X86_REG_RIP}
        else:
            return json.dumps({"error": f"Unsupported arch: {arch}. Use 'x86' or 'x86_64'"})

        # Map memory
        uc.mem_map(BASE_ADDR, 0x10000)
        uc.mem_write(BASE_ADDR, code)
        uc.mem_map(STACK_ADDR, STACK_SIZE)

        # Set stack pointer
        sp_reg = UC_X86_REG_ESP if arch == "x86" else UC_X86_REG_RSP
        uc.reg_write(sp_reg, STACK_ADDR + STACK_SIZE // 2)

        # Tracing
        trace = []
        mem_writes = []
        interrupts = []
        instruction_count = [0]

        def hook_code(uc, address, size, user_data):
            instruction_count[0] += 1
            if instruction_count[0] <= 50:  # Log first 50 instructions
                try:
                    code_bytes = uc.mem_read(address, size)
                    trace.append({"addr": hex(address), "size": size,
                                 "bytes": bytes(code_bytes).hex()})
                except Exception:
                    pass
            if instruction_count[0] >= max_instructions:
                uc.emu_stop()

        def hook_mem_write(uc, access, address, size, value, user_data):
            if len(mem_writes) < 30:
                mem_writes.append({"address": hex(address), "size": size,
                                   "value": hex(value & 0xFFFFFFFFFFFFFFFF)})

        def hook_interrupt(uc, intno, user_data):
            interrupts.append({"interrupt": intno, "instruction": instruction_count[0]})

        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
        uc.hook_add(UC_HOOK_INTR, hook_interrupt)

        # Emulate
        error_msg = None
        try:
            uc.emu_start(BASE_ADDR, BASE_ADDR + len(code), timeout=5000000)
        except Exception as e:
            error_msg = str(e)

        # Read final register state
        final_regs = {}
        for name, reg_id in reg_map.items():
            final_regs[name] = hex(uc.reg_read(reg_id))

        result = {
            "arch": arch,
            "code_size": len(code),
            "instructions_executed": instruction_count[0],
            "execution_trace": trace,
            "memory_writes": mem_writes,
            "interrupts": interrupts,
            "final_registers": final_regs,
        }

        if error_msg:
            result["emulation_error"] = error_msg

        # Behavioral observations
        behaviors = []
        if interrupts:
            behaviors.append(f"Made {len(interrupts)} interrupt/syscall calls")
        if mem_writes:
            behaviors.append(f"Wrote to {len(mem_writes)} memory locations")
        if instruction_count[0] >= max_instructions:
            behaviors.append("Hit instruction limit (may be in a loop)")
        result["behavioral_observations"] = behaviors

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# angr: Symbolic execution — find conditions that trigger malicious behavior
# ---------------------------------------------------------------------------
@function_tool
def analyze_binary_angr(file_path: str, find_address: str = "",
                        avoid_addresses: str = "",
                        max_time: int = 120, ctf=None) -> str:
    """
    Use angr symbolic execution to analyze a binary. Can automatically find
    inputs that reach specific code paths (e.g., malicious payload triggers),
    extract the control flow graph, and identify interesting functions.

    Args:
        file_path: Path to the binary to analyze
        find_address: Hex address to find a path to (e.g., '0x401234')
        avoid_addresses: Comma-separated hex addresses to avoid
        max_time: Maximum analysis time in seconds (default: 120)
    Returns:
        str: JSON with analysis results, CFG info, and symbolic execution outcome
    """
    try:
        import angr
    except ImportError:
        return json.dumps({"error": "angr not installed. Run: pip install angr"})

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        proj = angr.Project(file_path, auto_load_libs=False)

        result = {
            "file_path": file_path,
            "arch": str(proj.arch),
            "entry_point": hex(proj.entry),
            "min_addr": hex(proj.loader.min_addr),
            "max_addr": hex(proj.loader.max_addr),
        }

        # List loaded objects
        objects = []
        for obj in proj.loader.all_objects:
            objects.append({
                "name": obj.binary_basename if hasattr(obj, "binary_basename") else str(obj),
                "min_addr": hex(obj.min_addr),
                "max_addr": hex(obj.max_addr),
            })
        result["loaded_objects"] = objects

        # Function list from CFG
        try:
            cfg = proj.analyses.CFGFast()
            functions = []
            for addr, func in cfg.functions.items():
                functions.append({
                    "name": func.name,
                    "address": hex(addr),
                    "size": func.size,
                    "is_syscall": func.is_syscall,
                    "is_plt": func.is_plt,
                })
            result["functions"] = functions[:50]
            result["total_functions"] = len(functions)
            result["total_basic_blocks"] = len(cfg.graph.nodes())
        except Exception as e:
            result["cfg_error"] = str(e)

        # Symbolic execution if target address provided
        if find_address:
            try:
                target = int(find_address, 16)
                avoid_list = []
                if avoid_addresses:
                    avoid_list = [int(a.strip(), 16) for a in avoid_addresses.split(",")]

                state = proj.factory.entry_state()
                simgr = proj.factory.simgr(state)

                simgr.explore(find=target, avoid=avoid_list,
                             timeout=max_time)

                if simgr.found:
                    found_state = simgr.found[0]
                    solution = {
                        "found": True,
                        "target_address": find_address,
                        "input_bytes": found_state.posix.dumps(0).hex() if hasattr(found_state, "posix") else "N/A",
                    }
                    # Try to get stdin as string
                    try:
                        stdin_data = found_state.posix.dumps(0)
                        solution["input_string"] = stdin_data.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    result["symbolic_execution"] = solution
                else:
                    result["symbolic_execution"] = {
                        "found": False,
                        "target_address": find_address,
                        "note": "No path found to target address within time limit"
                    }
            except Exception as e:
                result["symbolic_execution_error"] = str(e)

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Frida: Runtime instrumentation — hook functions in running processes
# ---------------------------------------------------------------------------
@function_tool
def frida_hook(target: str, script: str = "", function_name: str = "",
               module_name: str = "", ctf=None) -> str:
    """
    Attach Frida to a running process and hook functions to inspect arguments,
    return values, and runtime behavior. Use for dynamic malware analysis.

    CAUTION: Only use on isolated/sandboxed systems. Never on production hosts.

    Args:
        target: Process name or PID to attach to
        script: Custom Frida JavaScript to inject (advanced)
        function_name: Function to hook (e.g., 'CreateFileW', 'connect')
        module_name: Module containing the function (e.g., 'kernel32.dll', 'libc.so')
    Returns:
        str: JSON with hooked function calls and their arguments
    """
    try:
        import frida
    except ImportError:
        return json.dumps({"error": "frida not installed. Run: pip install frida-tools"})

    if not script and not function_name:
        return json.dumps({"error": "Provide either a custom script or function_name to hook"})

    try:
        # Build script if not provided
        if not script and function_name:
            mod = module_name or "null"
            script = f"""
            var calls = [];
            Interceptor.attach(Module.findExportByName({json.dumps(mod if mod != "null" else None)}, "{function_name}"), {{
                onEnter: function(args) {{
                    var call_info = {{
                        "function": "{function_name}",
                        "timestamp": Date.now(),
                        "args": []
                    }};
                    for (var i = 0; i < Math.min(args.length || 6, 6); i++) {{
                        try {{
                            call_info.args.push(args[i].toString());
                        }} catch(e) {{
                            call_info.args.push("(unreadable)");
                        }}
                    }}
                    calls.push(call_info);
                    if (calls.length <= 50) {{
                        send(call_info);
                    }}
                }},
                onLeave: function(retval) {{
                    send({{
                        "function": "{function_name}",
                        "return_value": retval.toString()
                    }});
                }}
            }});
            """

        # Attach to process
        try:
            pid = int(target)
            session = frida.attach(pid)
        except ValueError:
            session = frida.attach(target)

        captured = []

        def on_message(message, data):
            if message["type"] == "send":
                captured.append(message["payload"])
            elif message["type"] == "error":
                captured.append({"error": message["description"]})

        script_obj = session.create_script(script)
        script_obj.on("message", on_message)
        script_obj.load()

        # Collect data for a short period
        import time
        time.sleep(5)

        script_obj.unload()
        session.detach()

        return json.dumps({
            "target": target,
            "function_hooked": function_name or "(custom script)",
            "captured_calls": captured[:50],
            "total_calls": len(captured),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# FindAES: Scan for AES keys in memory dumps
# ---------------------------------------------------------------------------
@function_tool
def find_aes_keys(file_path: str, ctf=None) -> str:
    """
    Scan a memory dump or binary for AES encryption keys using
    key schedule detection. Finds 128, 192, and 256-bit AES keys.
    Critical for memory forensics when dealing with encrypted malware.

    Args:
        file_path: Path to memory dump or binary to scan
    Returns:
        str: JSON with found AES keys, their offsets, and key sizes
    """
    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    # Try FindAES CLI first
    output = run_command(f'findaes "{file_path}" 2>/dev/null', ctf=ctf)

    if output and "Found" in output:
        return json.dumps({
            "file_path": file_path,
            "tool": "findaes",
            "results": output,
        }, indent=2)

    # Fallback: manual AES key schedule detection
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        keys_found = []

        # AES key schedule detection
        # AES-128: 10 rounds, AES-256: 14 rounds
        # Key schedules have specific mathematical relationships
        # between consecutive round keys

        # Simplified detection: look for high-entropy 16/32 byte
        # aligned blocks that could be key material
        BLOCK_SIZE = 16

        for offset in range(0, min(len(data) - BLOCK_SIZE, 100 * 1024 * 1024), 4):
            block = data[offset:offset + BLOCK_SIZE]

            # Check if block has characteristics of key material:
            # - Not all zeros or all same byte
            # - Reasonable entropy
            unique_bytes = len(set(block))
            if unique_bytes < 8:
                continue

            # Check for AES-128 key schedule pattern
            if offset + 176 <= len(data):  # 11 round keys * 16 bytes
                schedule = data[offset:offset + 176]
                if _verify_aes128_schedule(schedule):
                    keys_found.append({
                        "offset": hex(offset),
                        "key_size": 128,
                        "key_hex": block.hex(),
                    })

        result = {
            "file_path": file_path,
            "file_size": len(data),
            "scan_method": "key_schedule_detection",
            "keys_found": keys_found[:20],
            "total_keys": len(keys_found),
        }

        if keys_found:
            result["warning"] = "AES keys found — indicates encryption activity"

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


def _verify_aes128_schedule(schedule: bytes) -> bool:
    """Verify if a byte sequence looks like a valid AES-128 key schedule."""
    if len(schedule) < 176:
        return False

    try:
        # AES-128 key schedule: each round key is derived from the previous
        # Check that the schedule isn't trivially invalid
        words = []
        for i in range(0, 176, 4):
            words.append(int.from_bytes(schedule[i:i+4], "big"))

        # Basic validation: not all zeros, not all same, has variation
        if len(set(words)) < 10:
            return False

        # Check round key derivation (simplified check)
        # In AES-128, w[i] = w[i-4] XOR w[i-1] (with SubWord/RotWord for every 4th)
        valid_relations = 0
        for i in range(4, min(len(words), 44)):
            if i % 4 != 0:
                if words[i] == words[i-4] ^ words[i-1]:
                    valid_relations += 1

        # If >70% of non-boundary relations hold, likely a real schedule
        expected = 30  # 40 total words - 10 boundary words = 30 checkable
        return valid_relations > expected * 0.7
    except Exception:
        return False


