import re

with open("backend/orchestrator.py", "r") as f:
    content = f.read()

new_class_str = """class TerminalStream:
    def __init__(self, orchestrator, original_stdout):
        self.orchestrator = orchestrator
        self.original_stdout = original_stdout
        self.buffer = ""

    def write(self, s):
        self.original_stdout.write(s)
        self.original_stdout.flush()
        if not hasattr(self.orchestrator, "current_session") or not self.orchestrator.current_session:
            return
            
        if s.endswith('\\n'):
            line = self.buffer + s
            self.buffer = ""
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.orchestrator._send_dashboard_update('terminal_log', {'content': line}))
            except Exception:
                pass
        else:
            self.buffer += s

    def flush(self):
        self.original_stdout.flush()

class ForensicOrchestrator:"""

content = content.replace("class ForensicOrchestrator:", new_class_str)

old_loop_start = """    async def _investigation_loop(self, session_id: str):
        \"\"\"
        Main investigation loop — iteratively calls the DFIR Agent.
        Each step: build prompt → Runner.run(dfir_agent) → parse result → update state.
        \"\"\"
        state = self.state_manager.get_state(session_id)
        if not state:
            print(f"Error: No state found for session {session_id}")
            return

        step_number = 1

        try:
"""

new_loop_start = """    async def _investigation_loop(self, session_id: str):
        \"\"\"
        Main investigation loop — iteratively calls the DFIR Agent.
        Each step: build prompt → Runner.run(dfir_agent) → parse result → update state.
        \"\"\"
        import sys
        original_stdout = sys.stdout
        sys.stdout = TerminalStream(self, original_stdout)

        try:
            state = self.state_manager.get_state(session_id)
            if not state:
                print(f"Error: No state found for session {session_id}")
                return

            step_number = 1

            try:
"""

content = content.replace(old_loop_start, new_loop_start)

old_finally = """

        finally:
            # Wrap up investigation
            final_reasoning = "Investigation complete or max steps reached."
            await self._complete_investigation(state, final_reasoning)"""

new_finally = """

            finally:
                # Wrap up investigation
                final_reasoning = "Investigation complete or max steps reached."
                await self._complete_investigation(state, final_reasoning)
        finally:
            import sys
            sys.stdout = original_stdout"""

content = content.replace(old_finally, new_finally)

with open("backend/orchestrator.py", "w") as f:
    f.write(content)
