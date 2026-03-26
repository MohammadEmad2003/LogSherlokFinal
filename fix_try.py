with open("backend/orchestrator.py", "r") as f:
    lines = f.readlines()

new_lines = []
skip = False
for i, line in enumerate(lines):
    if line.strip() == "step_number = 1":
        new_lines.append(line)
        continue
    if "            try:" in line and "step_number = 1" in lines[i-2]:
        continue # skip the extra try
    new_lines.append(line)

with open("backend/orchestrator.py", "w") as f:
    f.writelines(new_lines)
