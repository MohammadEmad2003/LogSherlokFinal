with open("backend/orchestrator.py", "r") as f:
    lines = f.readlines()

in_try_block = False
for i, line in enumerate(lines):
    if line.strip() == "try:" and lines[i+1].strip() == "# Lazy-load Runner and agent":
        in_try_block = True
        continue
    
    if in_try_block:
        if line.startswith("        except Exception as e:") and 'print(f"Error in investigation loop: {e}")' in lines[i+1]:
            in_try_block = False
        else:
            if len(line.strip()) > 0 and line.startswith("            "):
                lines[i] = "    " + line

with open("backend/orchestrator.py", "w") as f:
    f.writelines(lines)
