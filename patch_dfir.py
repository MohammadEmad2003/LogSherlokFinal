with open("src/cai/agents/dfir.py", "r") as f:
    content = f.read()

import_stmt = "from cai.tools.forensics_salamanca.DISC import run_tsk_mft, run_plaso\n"

if "run_tsk_mft" not in content:
    content = content.replace("from cai.tools.misc.reasoning import think", "from cai.tools.misc.reasoning import think\n" + import_stmt)

tools_list = """tools = [
    generic_linux_command,
    run_ssh_command_with_credentials,
    execute_code,
    think,
    run_plaso,
    run_tsk_mft,
]"""

content = content.replace("""tools = [
    generic_linux_command,
    run_ssh_command_with_credentials,
    execute_code,
    think,
]""", tools_list)

with open("src/cai/agents/dfir.py", "w") as f:
    f.write(content)
