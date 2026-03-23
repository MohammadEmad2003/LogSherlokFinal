"""
A library to build Bug Bounty-level grade Cybersecurity AIs (CAIs).
"""

import os


def _normalize_openai_base_url(url: str) -> str:
    """Normalize OpenAI-compatible endpoint URLs to a client base URL.

    Accepts either:
    - https://host/v1
    - https://host/v1/chat/completions
    """
    normalized = url.strip().rstrip("/")
    suffix = "/chat/completions"
    if normalized.endswith(suffix):
        normalized = normalized[: -len(suffix)]
    return normalized


def _apply_cai_openai_base_url() -> None:
    """Resolve OpenAI-compatible base URL aliases into OPENAI_BASE_URL.

    Precedence:
    1) OPENAI_BASE_URL
    2) CAI_OPENAI_BASE_URL
    3) API_BASE
    """
    selected_base_url = (
        os.getenv("OPENAI_BASE_URL")
        or os.getenv("CAI_OPENAI_BASE_URL")
        or os.getenv("API_BASE")
    )
    if selected_base_url:
        os.environ["OPENAI_BASE_URL"] = _normalize_openai_base_url(selected_base_url)


def _apply_openai_api_key_aliases() -> None:
    """Resolve API key aliases into OPENAI_API_KEY.

    If OPENAI_API_KEY is not set, fallback to API_KEY for OpenAI-compatible
    providers and proxies.
    """
    if not os.getenv("OPENAI_API_KEY"):
        api_key = os.getenv("API_KEY")
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key


_apply_cai_openai_base_url()
_apply_openai_api_key_aliases()

def is_pentestperf_available():
    """
    Check if pentestperf is available
    """
    try:
        from pentestperf.ctf import CTF  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
    except ImportError:
        return False
    return True


def is_caiextensions_report_available():
    """
    Check if caiextensions report is available
    """
    try:
        from caiextensions.report.common import get_base_instructions  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
    except ImportError:
        return False
    return True


def is_caiextensions_memory_available():
    """
    Check if caiextensions memory is available
    """
    try:
        from caiextensions.memory import is_memory_installed  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
    except ImportError:
        return False
    return True


def is_caiextensions_platform_available():
    """
    Check if caiextensions-platform is available
    """
    try:
        from caiextensions.platform.base import platform_manager  # pylint: disable=import-error,import-outside-toplevel,unused-import  # noqa: E501,F401
    except ImportError:
        return False
    return True
