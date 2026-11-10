"""Runner comum: subprocess por lista, nunca shell=True com input do LLM."""
from __future__ import annotations

import subprocess
import time

from agent_schemas import ToolResult


def run_cmd(cmd: list[str], timeout: int = 120) -> ToolResult:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "")[:8000]
        err = (p.stderr or "")[:8000]
        return ToolResult(
            exit_code=p.returncode,
            stdout=out,
            stderr=err,
            duration_ms=int((time.time() - t0) * 1000),
            command=" ".join(cmd),
            summary=(out or err)[:4000],
        )
    except subprocess.TimeoutExpired:
        return ToolResult(
            exit_code=124,
            stdout="",
            stderr=f"timeout apos {timeout}s",
            duration_ms=int((time.time() - t0) * 1000),
            command=" ".join(cmd),
            summary="timeout",
        )
    except FileNotFoundError as e:
        return ToolResult(
            exit_code=127,
            stdout="",
            stderr=str(e),
            duration_ms=0,
            command=" ".join(cmd),
            summary=f"binario nao encontrado: {cmd[0]}",
        )


def has_binary(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None
