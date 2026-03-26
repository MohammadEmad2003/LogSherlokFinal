import re

with open("ui/dashboard.js", "r") as f:
    content = f.read()

handler_code = """
        case "full_state":
            handleFullState(message.data);
            break;
        case "terminal_log":
            handleTerminalLog(message.data);
            break;
"""

content = content.replace("""
        case "full_state":
            handleFullState(message.data);
            break;
""", handler_code)

func_code = """
function handleTerminalLog(data) {
    const feed = document.getElementById("terminal-feed");
    if (!feed) return;
    
    const line = document.createElement("div");
    line.style.marginBottom = "2px";
    
    // Simple sanitization
    let text = (data.content || "").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    
    // Add color for timestamps or tags if desired
    text = text.replace(/\\[(.*?)\\]/g, '<span style="color:#88ccff">[$1]</span>');
    line.innerHTML = text;
    
    feed.appendChild(line);
    
    // Autoscroll
    feed.scrollTop = feed.scrollHeight;
}

// Clear terminal button
document.addEventListener("DOMContentLoaded", () => {
    const clearBtn = document.getElementById("clear-term-btn");
    if (clearBtn) {
        clearBtn.addEventListener("click", () => {
            document.getElementById("terminal-feed").innerHTML = "";
        });
    }
});
"""

content += "\n" + func_code

with open("ui/dashboard.js", "w") as f:
    f.write(content)
