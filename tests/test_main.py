import pytest

import main


def test_check_verifica_nikto():
    assert "nikto" in main.CHECK_BINARIES


def test_check_verifica_wapiti():
    assert "wapiti" in main.CHECK_BINARIES


def test_load_config():
    cfg = main.load_config()
    assert cfg["target"]["base_url"] == "http://localhost:3000"
    assert cfg["model"]["name"] == "qwen3:4b"
    assert cfg["model"]["num_ctx"] == 4096
    assert set(cfg["target"]["allowed_hosts"]) == {"localhost", "127.0.0.1", "juice-shop"}


def test_build_prewarm_payload_via_client():
    from agent.ollama_client import build_prewarm_payload
    cfg = main.load_config()
    p = build_prewarm_payload(cfg["model"]["name"], cfg["model"]["num_ctx"])
    assert p["think"] is False
    assert p["options"]["num_ctx"] == cfg["model"]["num_ctx"]


def test_resolve_unique_run_id_sem_conflito(tmp_path):
    assert main.resolve_unique_run_id(tmp_path, "recon") == "recon"


def test_resolve_unique_run_id_evita_colisao(tmp_path):
    (tmp_path / "recon").mkdir()
    assert main.resolve_unique_run_id(tmp_path, "recon") == "recon-2"


def test_resolve_unique_run_id_incrementa_ate_achar_dir_livre(tmp_path):
    (tmp_path / "recon").mkdir()
    (tmp_path / "recon-2").mkdir()
    assert main.resolve_unique_run_id(tmp_path, "recon") == "recon-3"


def test_resolve_unique_run_id_dir_vazio_tambem_colide(tmp_path):
    # id unico por diretoria: recriar por cima de execucao anterior sempre evita perda de evidencia
    (tmp_path / "recon").mkdir()
    assert main.resolve_unique_run_id(tmp_path, "recon") != "recon"


def test_main_sem_args_sem_tty_falha_com_mensagem(monkeypatch, capsys):
    import sys
    import io
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))  # nao eh tty
    monkeypatch.setattr(sys, "argv", ["main.py"])
    with pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 2


def test_cmd_run_propaga_fase_e_flags_conhecimento(monkeypatch, tmp_path):
    import sys
    captured = {}
    fake_cfg = {
        "target": {"base_url": "http://localhost:3000",
                   "allowed_hosts": ["localhost", "127.0.0.1", "juice-shop"]},
        "model": {"name": "qwen3:4b", "endpoint": "http://localhost:11434/api/chat"},
        "paths": {"seclists": "wordlists/SecLists", "runs": str(tmp_path / "runs")},
        "limits": {"max_iter": 3, "tool_timeout_sec": 10, "max_output_chars": 8000},
    }
    monkeypatch.setattr(main, "check_lab", lambda cfg: None)
    monkeypatch.setattr(main, "generate_summary_md", lambda iid: None)
    monkeypatch.setattr(main, "load_config", lambda: fake_cfg)
    monkeypatch.setattr(main, "run_investigation",
                        lambda *a, **kw: captured.update(kw))
    monkeypatch.setattr(main, "EvidenceStore",
                        lambda d: type("S", (), {"list": lambda self, iid: []})())
    import yaml
    cv = tmp_path / "inv.yaml"
    cv.write_text(yaml.dump({
        "objective": "validar sqli",
        "investigation_id": "inv-fase",
        "conhecimento": {"endpoints": ["/rest/user?q="],
                          "suspeita": "sqli no parametro q"},
    }), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["main.py", "run", "--file", str(cv)])
    main.main()
    assert captured["fase_inicial"] == 3
    assert "sqli_suspeita" in captured["flags_iniciais"]
    assert "endpoint_conhecido" in captured["flags_iniciais"]


def test_cmd_run_sem_conhecimento_comeca_no_recon(monkeypatch, tmp_path):
    import sys
    captured = {}
    fake_cfg = {
        "target": {"base_url": "http://localhost:3000",
                   "allowed_hosts": ["localhost", "127.0.0.1", "juice-shop"]},
        "model": {"name": "qwen3:4b", "endpoint": "http://localhost:11434/api/chat"},
        "paths": {"seclists": "wordlists/SecLists", "runs": str(tmp_path / "runs")},
        "limits": {"max_iter": 3, "tool_timeout_sec": 10, "max_output_chars": 8000},
    }
    monkeypatch.setattr(main, "check_lab", lambda cfg: None)
    monkeypatch.setattr(main, "generate_summary_md", lambda iid: None)
    monkeypatch.setattr(main, "load_config", lambda: fake_cfg)
    monkeypatch.setattr(main, "run_investigation",
                        lambda *a, **kw: captured.update(kw))
    monkeypatch.setattr(main, "EvidenceStore",
                        lambda d: type("S", (), {"list": lambda self, iid: []})())
    import yaml
    cv = tmp_path / "inv2.yaml"
    cv.write_text(yaml.dump({"objective": "recon", "investigation_id": "inv-recon"}),
                  encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["main.py", "run", "--file", str(cv)])
    main.main()
    assert captured["fase_inicial"] == 1
    assert captured["flags_iniciais"] == []


def test_intake_interativo_com_conhecimento_pula_recon(monkeypatch):
    from unittest import mock
    answers = iter(["validar sqli no Juice Shop",   # situacao
                    "sqli no parametro q",          # suspeita
                    "/rest/user?q=",                # endpoints
                    "",                              # evidencias
                    "3"])                            # fase (aceita default)
    with mock.patch.object(main, "Prompt") as PromptMock:
        PromptMock.ask.side_effect = lambda *a, **kw: next(answers)
        objetivo, fase, flags = main._intake_interativo()
    assert objetivo == "validar sqli no Juice Shop"
    assert fase == 3
    assert "sqli_suspeita" in flags and "endpoint_conhecido" in flags


def test_intake_interativo_sempre_comeca_no_recon_sem_conhecimento(monkeypatch):
    from unittest import mock
    answers = iter(["reconhecimento do alvo", "", "", "", "1"])
    with mock.patch.object(main, "Prompt") as PromptMock:
        PromptMock.ask.side_effect = lambda *a, **kw: next(answers)
        objetivo, fase, flags = main._intake_interativo()
    assert fase == 1
    assert flags == []
