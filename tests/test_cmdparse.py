import pytest

from tools import cmdparse

URL = "http://localhost:3000"


def test_nmap_alvo_simples():
    p = cmdparse.parse_command("nmap", f"nmap {URL}")
    assert p == {"target": "localhost"}


def test_nmap_com_extra_args():
    p = cmdparse.parse_command("nmap", "nmap -sV -p 3000 localhost")
    assert p["target"] == "localhost"
    assert p["extra_args"] == "-sV -p 3000"


def test_nmap_extra_args_com_script_bloqueado():
    with pytest.raises(ValueError):
        cmdparse.parse_command("nmap", "nmap --script=banner localhost")


def test_nmap_host_externo_rejeitado():
    with pytest.raises(ValueError):
        cmdparse.parse_command("nmap", "nmap example.com")


def test_nmap_sem_alvo_erro():
    with pytest.raises(ValueError, match="alvo"):
        cmdparse.parse_command("nmap", "nmap -sV")


def test_http_request_url_simples():
    p = cmdparse.parse_command("http_request", f"http_request {URL}/x")
    assert p == {"url": f"{URL}/x"}


def test_http_request_curl_com_header():
    p = cmdparse.parse_command("http_request",
                               f"curl {URL} -H 'Accept: application/json'")
    assert p["url"] == URL
    assert p["headers"] == {"Accept": "application/json"}


def test_http_request_host_externo_rejeitado():
    with pytest.raises(ValueError):
        cmdparse.parse_command("http_request", "http_request http://example.com")


def test_http_request_post_com_x_session_e_data():
    p = cmdparse.parse_command(
        "http_request",
        f"http_request {URL}/rest/user/login -X POST -H 'Content-Type: application/json' "
        f"--data '{{\"email\":\"a@b.c\"}}' --session A")
    assert p["method"] == "POST"
    assert p["session"] == "A"
    assert p["body"] == '{"email":"a@b.c"}'
    assert p["headers"]["Content-Type"] == "application/json"


def test_http_request_flag_d_alias_de_body():
    p = cmdparse.parse_command("http_request", f"http_request {URL}/x -d 'a=b'")
    assert p["body"] == "a=b"


def test_http_request_request_longo_e_metodo_minusculo():
    p = cmdparse.parse_command("http_request", f"http_request {URL} --request post")
    assert p["method"] == "POST"


def test_http_request_metodo_invalido_rejeitado():
    with pytest.raises(ValueError, match="metodo"):
        cmdparse.parse_command("http_request", f"http_request {URL} -X HACK")


def test_http_request_sessao_nome_invalido_rejeitado():
    with pytest.raises(ValueError, match="sessao"):
        cmdparse.parse_command("http_request", f"http_request {URL} --session '../x'")


def test_preview_http_mostra_metodo_e_sessao():
    out = cmdparse.preview_command(
        "http_request",
        {"url": f"{URL}/login", "method": "POST",
         "headers": {"Content-Type": "application/json"}, "body": "{}", "session": "A"})
    assert out.startswith("POST ")
    assert "session=A" in out


def test_gobuster_comando_completo():
    p = cmdparse.parse_command("gobuster",
        f"gobuster dir -u {URL} -w Discovery/Web-Content/common.txt --exclude-length 9984")
    assert p["url"] == URL
    assert p["wordlist"] == "Discovery/Web-Content/common.txt"
    assert p["exclude_length"] == "9984"


def test_gobuster_wordlist_fora_do_seclists_rejeitada():
    with pytest.raises(ValueError):
        cmdparse.parse_command("gobuster", f"gobuster dir -u {URL} -w /etc/passwd")


def test_gobuster_flag_desconhecida_rejeitada():
    with pytest.raises(ValueError, match="-x"):
        cmdparse.parse_command("gobuster", f"gobuster dir -u {URL} -x php,html")


def test_wfuzz_comando_completo():
    p = cmdparse.parse_command("wfuzz",
        f"wfuzz -c -z file,Fuzzing/Databases/SQLi/quick-SQLi.txt -u {URL}/s?q=FUZZ --hc 404")
    assert p["url"] == f"{URL}/s?q=FUZZ"
    assert p["wordlist"] == "Fuzzing/Databases/SQLi/quick-SQLi.txt"
    assert p["extra_args"] == "--hc 404"


def test_wfuzz_sem_fuzz_rejeitado():
    with pytest.raises(ValueError, match="FUZZ"):
        cmdparse.parse_command("wfuzz",
            f"wfuzz -z file,Fuzzing/Databases/SQLi/quick-SQLi.txt -u {URL}/plain")


def test_wfuzz_flag_desconhecida_rejeitada():
    with pytest.raises(ValueError, match="wfuzz nao suportada"):
        cmdparse.parse_command("wfuzz",
            f"wfuzz -z file,Fuzzing/Databases/SQLi/quick-SQLi.txt -u {URL}/s?q=FUZZ -p 127.0.0.1:8080")


def test_wapiti_comando_completo():
    p = cmdparse.parse_command("wapiti", f"wapiti -u {URL} -m sql,xss --scope url -l 2")
    assert p["modules"] == ["sql", "xss"] and p["scope"] == "url" and str(p["level"]) == "2"


def test_wapiti_modulo_desconhecido_rejeitado():
    with pytest.raises(ValueError):
        cmdparse.parse_command("wapiti", f"wapiti -u {URL} -m modulo_inexistente")


def test_wapiti_maxtime_aceita_sufixo_s():
    p = cmdparse.parse_command("wapiti", f"wapiti -u {URL} --max-scan-time 120s")
    assert str(p["max_scan_time"]) == "120"


def test_nikto_comando_completo():
    p = cmdparse.parse_command("nikto", f"nikto -h {URL} -Tuning 9 -maxtime 120s")
    assert p["tuning"] == "9" and str(p["maxtime"]) == "120"


def test_nikto_tuning_invalido_rejeitado():
    with pytest.raises(ValueError):
        cmdparse.parse_command("nikto", f"nikto -h {URL} -Tuning 9;rm")


def test_shlex_malformado_erro_claro():
    with pytest.raises(ValueError, match="mal formado"):
        cmdparse.parse_command("nmap", "nmap 'unterminated quote")


def test_preview_gobuster_mostra_comando():
    out = cmdparse.preview_command("gobuster", {"url": URL,
                                                "wordlist": "Discovery/Web-Content/common.txt"})
    assert out.startswith("gobuster dir -u") and "-w" in out


def test_preview_nmap_duas_fases():
    out = cmdparse.preview_command("nmap", {"target": URL})
    assert "duas fases" in out


def test_preview_nmap_extra_args_single_shot():
    out = cmdparse.preview_command("nmap", {"target": URL, "extra_args": "-sV -p 3000"})
    assert out == "nmap -sV -p 3000 localhost"


def test_preview_wapiti():
    out = cmdparse.preview_command("wapiti", {"url": URL, "modules": ["sql"]})
    assert "wapiti -u" in out and "-m sql" in out
