import pytest
from pydantic import ValidationError

from agent_schemas import ActionProposal, HumanDecision, ToolResult


@pytest.mark.parametrize("tool", ["nmap", "http_request", "gobuster", "wfuzz"])
def test_action_proposal_tool_valida(tool):
    p = ActionProposal(tool=tool, params={}, hypothesis="h", rationale="r")
    assert p.tool == tool
    assert p.risk == "baixo"
    assert p.expected_evidence == ""


def test_action_proposal_tool_desconhecida_falha():
    with pytest.raises(ValidationError):
        ActionProposal(tool="nc", params={}, hypothesis="h", rationale="r")


def test_action_proposal_campos_obrigatorios():
    with pytest.raises(ValidationError):
        ActionProposal(tool="nmap", params={}, rationale="r")


@pytest.mark.parametrize("action", ["approved", "modified", "rejected"])
def test_human_decision_acoes_permitidas(action):
    assert HumanDecision(action=action).action == action


def test_human_decision_acao_invalida_falha():
    with pytest.raises(ValidationError):
        HumanDecision(action="maybe")


def test_tool_result_monta_completo():
    r = ToolResult(exit_code=0, stdout="o", stderr="e",
                   duration_ms=12, command="c", summary="s")
    assert r.exit_code == 0
    assert r.duration_ms == 12


def test_tool_result_campos_faltando_falham():
    with pytest.raises(ValidationError):
        ToolResult(exit_code=0, stdout="o")
