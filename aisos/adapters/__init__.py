"""
aisos/adapters
~~~~~~~~~~~~~~~
Framework integration adapters and SDK auto-patchers for AI SOS.
"""

from aisos.adapters.fastapi import AISOSFastAPIMiddleware
from aisos.adapters.flask import AISOSFlaskMiddleware
from aisos.adapters.django import AISOSDjangoMiddleware
from aisos.adapters.sdk_patcher import auto_patch_all, patch_openai, patch_anthropic, patch_httpx, patch_requests

__all__ = [
    "AISOSFastAPIMiddleware",
    "AISOSFlaskMiddleware",
    "AISOSDjangoMiddleware",
    "auto_patch_all",
    "patch_openai",
    "patch_anthropic",
    "patch_httpx",
    "patch_requests",
]
