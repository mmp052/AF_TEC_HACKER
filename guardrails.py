"""Validacao de alvo e de parametros contra alucinação do LLM."""
from __future__ import annotations

from urllib.parse import urlparse

ALLOWED_HOSTS = {"localhost", "127.0.0.1", "juice-shop"}


def validate_url(url: str, allowed_hosts: set[str] | None = None) -> None:
    hosts = allowed_hosts or ALLOWED_HOSTS
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"esquema nao permitido: {parsed.scheme}")
    if parsed.hostname not in hosts:
        raise ValueError(f"host nao permitido: {parsed.hostname!r}. permitidos: {sorted(hosts)}")


def validate_nmap_args(args: list[str]) -> None:
    blocked = {"-oX", "-oA", "--script", "-iL", "--open", "-T4", "-T5", "-sn"}
    joined = " ".join(args)
    for b in ["-oX", "-oA", "--script=", "-iL"]:
        if b in joined:
            raise ValueError(f"argumento nmap bloqueado: {b}")
