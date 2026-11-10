"""Schemas pydantic do contrato LLM -> humano -> ferramenta."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ActionProposal(BaseModel):
    tool: Literal["nmap", "http_request", "gobuster", "wfuzz", "conclude"]
    params: dict
    hypothesis: str
    rationale: str
    risk: str = "baixo"
    expected_evidence: str = ""


class HumanDecision(BaseModel):
    action: Literal["approved", "modified", "rejected"]
    final_params: dict | None = None
    note: str = ""


class ToolResult(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    command: str
    summary: str
