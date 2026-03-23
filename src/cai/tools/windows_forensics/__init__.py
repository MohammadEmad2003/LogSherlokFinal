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
from cai.tools.windows_forensics.chainsaw_tool import (
    build_chainsaw_plan,
    build_chainsaw_plan_dict,
)
from cai.tools.windows_forensics.recmd_tool import (
    build_recmd_plan,
    build_recmd_plan_dict,
)

TOOL_REGISTRY = {
    "build_evtxecmd_plan": build_evtxecmd_plan,
    "build_hayabusa_plan": build_hayabusa_plan,
    "build_pecmd_plan": build_pecmd_plan,
    "build_chainsaw_plan": build_chainsaw_plan,
    "build_recmd_plan": build_recmd_plan,
}

__all__ = [
    "TOOL_REGISTRY",
    "build_evtxecmd_plan",
    "build_evtxecmd_plan_dict",
    "build_hayabusa_plan",
    "build_hayabusa_plan_dict",
    "build_pecmd_plan",
    "build_pecmd_plan_dict",
    "build_chainsaw_plan",
    "build_chainsaw_plan_dict",
    "build_recmd_plan",
    "build_recmd_plan_dict",
]
