"""Windows forensic tool wrappers integrated for CAI."""

from cai.tools.windows_forensics.evtxecmd_tool import (
    build_evtxecmd_plan,
    build_evtxecmd_plan_dict,
)
from cai.tools.windows_forensics.hayabusa_tool import (
    build_hayabusa_plan,
    build_hayabusa_plan_dict,
)
from cai.tools.windows_forensics.pecmd_tool import (
    build_pecmd_plan,
    build_pecmd_plan_dict,
)

TOOL_REGISTRY = {
    "build_evtxecmd_plan": build_evtxecmd_plan,
    "build_hayabusa_plan": build_hayabusa_plan,
    "build_pecmd_plan": build_pecmd_plan,
}

__all__ = [
    "TOOL_REGISTRY",
    "build_evtxecmd_plan",
    "build_evtxecmd_plan_dict",
    "build_hayabusa_plan",
    "build_hayabusa_plan_dict",
    "build_pecmd_plan",
    "build_pecmd_plan_dict",
]
