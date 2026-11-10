import pytest

from routing.wordlist import (
    choose_wordlist,
    describe_choice,
    FALLBACK_GOBUSTER,
    FALLBACK_WFUZZ_SQLI,
)


def test_sem_historia_usa_fallback_generico():
    assert choose_wordlist("gobuster", []) == (FALLBACK_GOBUSTER, "fallback_generico")
    assert choose_wordlist("wfuzz", []) == (FALLBACK_WFUZZ_SQLI, "fallback_generico")


def test_ferramenta_nao_aplicavel():
    assert choose_wordlist("nmap", []) == ("", "nao_aplicavel")
    assert choose_wordlist("http_request", [{"result_summary": "wordpress"}]) == ("", "nao_aplicavel")


@pytest.mark.parametrize("hist", [
    [{"result_summary": "Server: WordPress/6.4 /wp-admin wp-content"}],
    [{"stdout": "... wp-content themes ..."}],
    [{"interpretation": "pagina expoe /wp-includes/"}],
])
def test_evidencia_wordpress_escolhe_wordlists_cms(hist):
    wl_g, mot_g = choose_wordlist("gobuster", hist)
    wl_w, mot_w = choose_wordlist("wfuzz", hist)
    assert "wordpress" in wl_g.lower()
    assert mot_g == "evidencia_tech:wordpress"
    assert "wordpress" in wl_w.lower()
    assert mot_w == "evidencia_tech:wordpress"


def test_evidencia_erro_sql_escolhe_sqli():
    hist = [{"result_summary": "You have an error in your SQL syntax near"}]
    wl, motivo = choose_wordlist("wfuzz", hist)
    assert motivo == "evidencia_falha:sql_error"
    assert "SQLi" in wl


def test_evidencia_nosql_escolhe_nosql():
    hist = [{"interpretation": "mongodb error tipo NoSQL"}]
    assert choose_wordlist("wfuzz", hist) == ("Fuzzing/Databases/SQLi/NoSQL.txt", "evidencia_falha:nosql")


def test_evidencia_xss_refletido():
    hist = [{"result_summary": "<script>alert(1)</script> refletido em q"}]
    wl, motivo = choose_wordlist("wfuzz", hist)
    assert "XSS" in wl.upper()
    assert motivo == "evidencia_falha:xss_reflected"


def test_evidencia_ssti():
    hist = [{"result_summary": "{{7*7}} renderizado como 49 (jinja)"}]
    wl, motivo = choose_wordlist("wfuzz", hist)
    assert motivo == "evidencia_falha:ssti"


def test_evidencia_lfi_path_traversal():
    hist = [{"result_summary": "../../etc/passwd retornou dados"}]
    wl, motivo = choose_wordlist("wfuzz", hist)
    assert motivo == "evidencia_falha:lfi_path_traversal"
    assert "LFI" in wl


def test_evidencia_api_choose_mesmo_com_swagger():
    hist = [{"result_summary": "encontrado swagger.json e openapi"}]
    wl, motivo = choose_wordlist("gobuster", hist)
    assert motivo == "evidencia_tech:api"


def test_motivo_descrever_com_evidencia_e_fallback():
    hist = [{"result_summary": "wordpress"}]
    wl, motivo = choose_wordlist("gobuster", hist)
    assert "wordpress" in describe_choice("gobuster", wl, motivo).lower()
    assert "generico" in describe_choice("gobuster", "x", "fallback_generico")
    assert "nao aplicavel" in describe_choice("nmap", "", "nao_aplicavel")


def test_apache_sem_framework_prefere_lista_generica_raft():
    hist = [{"result_summary": "80/tcp open http Apache httpd 2.4.66 ((Ubuntu))\n8000/tcp open http Apache httpd"}]
    wl, motivo = choose_wordlist("gobuster", hist)
    assert wl == "Discovery/Web-Content/raft-small-directories.txt"
    assert motivo == "evidencia_tech:apache"


def test_nginx_sem_framework_prefere_lista_generica_raft():
    hist = [{"result_summary": "80/tcp open http nginx 1.27.0"}]
    wl, motivo = choose_wordlist("gobuster", hist)
    assert wl == "Discovery/Web-Content/raft-small-directories.txt"


def test_wordpress_ainda_ganha_da_regra_generica():
    hist = [{"result_summary": "Apache httpd 2.4.66\nhttp://x/wp-content/themes"}]
    wl, motivo = choose_wordlist("gobuster", hist)
    assert "wordpress" in wl
