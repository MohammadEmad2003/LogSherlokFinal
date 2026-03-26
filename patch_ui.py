import re

with open("ui/dashboard.html", "r") as f:
    content = f.read()

# Add a terminal panel to the bottom of the left column
terminal_panel = """                        <!-- Terminal Logs Panel -->
                        <div class="panel terminal-panel">
                            <div class="panel-header">
                                <h2><i class="fas fa-terminal"></i> Terminal Logs</h2>
                                <div class="header-actions">
                                    <button class="icon-btn" id="clear-term-btn" title="Clear Logs">
                                        <svg viewBox="0 0 24 24" width="16" height="16"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" fill="currentColor"/></svg>
                                    </button>
                                </div>
                            </div>
                            <div class="panel-content terminal-content" id="terminal-feed" style="background:#1e1e1e; color:#00ff00; font-family:monospace; padding:10px; overflow-y:auto; font-size:12px;">
                            </div>
                        </div>

                        <div class="panel chat-panel llm-chat">"""

content = content.replace('<div class="panel chat-panel llm-chat">', terminal_panel)

# Oh wait, left-col ends before Chat panel actually in standard setup? Let's verify exactly where Chat panel is.
with open("ui/dashboard.html", "w") as f:
    f.write(content)
