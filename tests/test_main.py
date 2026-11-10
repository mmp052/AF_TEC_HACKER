import main


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
