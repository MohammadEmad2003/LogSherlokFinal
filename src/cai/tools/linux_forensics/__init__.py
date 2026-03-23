"""Linux forensic tool wrappers integrated for CAI."""

from cai.tools.linux_forensics.ausearch_tool import (
    build_ausearch_plan,
    build_ausearch_plan_dict,
)
from cai.tools.linux_forensics.journalctl_tool import (
    build_journalctl_plan,
    build_journalctl_plan_dict,
)
from cai.tools.linux_forensics.lsof_tool import (
    build_lsof_plan,
    build_lsof_plan_dict,
)
from cai.tools.linux_forensics.osquery_tool import (
    build_osquery_plan,
    build_osquery_plan_dict,
)
from cai.tools.linux_forensics.ss_tool import (
    build_ss_plan,
    build_ss_plan_dict,
)

TOOL_REGISTRY = {
    "build_journalctl_plan": build_journalctl_plan,
    "build_ausearch_plan": build_ausearch_plan,
    "build_osquery_plan": build_osquery_plan,
    "build_ss_plan": build_ss_plan,
    "build_lsof_plan": build_lsof_plan,
}

__all__ = [
    "TOOL_REGISTRY",
    "build_journalctl_plan",
    "build_journalctl_plan_dict",
    "build_ausearch_plan",
    "build_ausearch_plan_dict",
    "build_osquery_plan",
    "build_osquery_plan_dict",
    "build_ss_plan",
    "build_ss_plan_dict",
    "build_lsof_plan",
    "build_lsof_plan_dict",
]
