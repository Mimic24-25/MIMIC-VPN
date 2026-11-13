#!/usr/bin/env python3
"""Build a single MIMIC VPN subscription from three sources.

All sources must be fetched successfully before the output file is replaced.
The V2Hub URL is read only from the V2HUB_SUB_URL environment variable.
"""
import base64
import concurrent.futures
import json
import subprocess
import tempfile
import shutil
import time
import os
import re
import sys
import socket
import urllib.request
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit, parse_qs

SOURCES = [
    ("V2Hub", os.environ.get("V2HUB_SUB_URL", "").strip()),
    ("VlessForU", "https://sub.vlessfo.ru/vlessforu/working_configs.txt"),
    ("Blacklist", "https://raw.githubusercontent.com/Buffetbarko/Universal-Proxy-Config-Parser-/main/blacklist_vpn.txt"),
]
OUT = Path("mimic-vpn.txt")
SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hy2://", "hysteria2://", "tuic://", "socks://")

FLAGS = {
    "US":"США","DE":"Германия","NL":"Нидерланды","GB":"Великобритания","UK":"Великобритания",
    "FR":"Франция","FI":"Финляндия","SE":"Швеция","NO":"Норвегия","CH":"Швейцария",
    "AT":"Австрия","PL":"Польша","CZ":"Чехия","ES":"Испания","IT":"Италия","PT":"Португалия",
    "TR":"Турция","RU":"Россия","UA":"Украина","BY":"Беларусь","KZ":"Казахстан",
    "JP":"Япония","SG":"Сингапур","HK":"Гонконг","KR":"Южная Корея","IN":"Индия",
    "CA":"Канада","AU":"Австралия","BR":"Бразилия","AR":"Аргентина","RO":"Румыния",
    "BG":"Болгария","GR":"Греция","HU":"Венгрия","IE":"Ирландия","BE":"Бельгия",
    "LT":"Литва","LV":"Латвия","EE":"Эстония","IS":"Исландия","MD":"Молдова",
}
FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")

def fetch(name, url):
    if not url:
        raise RuntimeError("Не задан GitHub Secret V2HUB_SUB_URL")
    req = urllib.request.Request(url, headers={"User-Agent":"MIMIC-VPN-Subscription/1.0"})
    with urllib.request.urlopen(req, timeout=35) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise RuntimeError(f"{name}: источник больше 8 МБ")
    return raw.decode("utf-8-sig", errors="replace")

def decode_payload(text):
    text = text.strip()
    if any(s in text.lower() for s in SCHEMES):
        return text
    compact = re.sub(r"\s+", "", text)
    if compact and re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", "ignore")
            if any(s in decoded.lower() for s in SCHEMES):
                return decoded
        except Exception:
            pass
    return text

def extract_uris(payload):
    payload = decode_payload(payload)
    found = []
    for line in payload.splitlines():
        line = line.strip().strip("\ufeff")
        if not line or line.startswith(("#", ";")):
            continue
        # A source may place multiple links on one line.
        for match in re.finditer(r"(?i)(?:vless|vmess|trojan|ss|hy2|hysteria2|tuic|socks)://[^\s<>\"']+", line):
            uri = match.group(0).rstrip("),;]")
            if uri.lower().startswith(SCHEMES):
                found.append(uri)
    return found

COUNTRY_NAMES = {
    "US":"США","DE":"Германия","NL":"Нидерланды","GB":"Великобритания","FR":"Франция",
    "FI":"Финляндия","SE":"Швеция","NO":"Норвегия","CH":"Швейцария","AT":"Австрия",
    "PL":"Польша","CZ":"Чехия","ES":"Испания","IT":"Италия","PT":"Португалия","TR":"Турция",
    "RU":"Россия","UA":"Украина","BY":"Беларусь","KZ":"Казахстан","JP":"Япония","SG":"Сингапур",
    "HK":"Гонконг","KR":"Южная Корея","IN":"Индия","CA":"Канада","AU":"Австралия","BR":"Бразилия",
    "AR":"Аргентина","RO":"Румыния","BG":"Болгария","GR":"Греция","HU":"Венгрия","IE":"Ирландия",
    "BE":"Бельгия","LT":"Литва","LV":"Латвия","EE":"Эстония","IS":"Исландия","MD":"Молдова",
    "CY":"Кипр","DK":"Дания","LU":"Люксембург","MT":"Мальта","SK":"Словакия","SI":"Словения",
    "HR":"Хорватия","RS":"Сербия","BA":"Босния и Герцеговина","ME":"Черногория","MK":"Северная Македония",
    "AL":"Албания","XK":"Косово","GE":"Грузия","AM":"Армения","AZ":"Азербайджан","IL":"Израиль",
    "AE":"ОАЭ","SA":"Саудовская Аравия","QA":"Катар","KW":"Кувейт","BH":"Бахрейн","OM":"Оман",
    "JO":"Иордания","LB":"Ливан","EG":"Египет","MA":"Марокко","TN":"Тунис","ZA":"ЮАР",
    "NG":"Нигерия","KE":"Кения","GH":"Гана","ET":"Эфиопия","PK":"Пакистан","BD":"Бангладеш",
    "LK":"Шри-Ланка","NP":"Непал","TH":"Таиланд","VN":"Вьетнам","MY":"Малайзия","ID":"Индонезия",
    "PH":"Филиппины","TW":"Тайвань","KH":"Камбоджа","LA":"Лаос","MM":"Мьянма","MN":"Монголия",
    "NZ":"Новая Зеландия","MX":"Мексика","CL":"Чили","CO":"Колумбия","PE":"Перу","UY":"Уругвай",
    "EC":"Эквадор","CR":"Коста-Рика","PA":"Панама","DO":"Доминиканская Республика","VE":"Венесуэла",
    "BO":"Боливия","PY":"Парагвай","GT":"Гватемала","CU":"Куба","JM":"Ямайка","TT":"Тринидад и Тобаго",
    "UZ":"Узбекистан","KG":"Кыргызстан","TJ":"Таджикистан","TM":"Туркменистан","AF":"Афганистан",
    "IQ":"Ирак","IR":"Иран","SY":"Сирия","YE":"Йемен","LY":"Ливия","DZ":"Алжир","SD":"Судан",
    "TZ":"Танзания","UG":"Уганда","SN":"Сенегал","CM":"Камерун","CI":"Кот-д’Ивуар","AO":"Ангола",
    "ZM":"Замбия","ZW":"Зимбабве","MU":"Маврикий","SC":"Сейшелы","FJ":"Фиджи","GU":"Гуам",
    "PR":"Пуэрто-Рико","GI":"Гибралтар","IM":"Остров Мэн","JE":"Джерси","GG":"Гернси",
}
FLAGS = {**FLAGS, "DK":"Дания","CY":"Кипр","LU":"Люксембург","MT":"Мальта","SK":"Словакия",
         "SI":"Словения","HR":"Хорватия","RS":"Сербия","BA":"Босния и Герцеговина",
         "ME":"Черногория","MK":"Северная Македония","AL":"Албания","GE":"Грузия","AM":"Армения",
         "AZ":"Азербайджан","IL":"Израиль","AE":"ОАЭ","SA":"Саудовская Аравия","QA":"Катар",
         "KW":"Кувейт","BH":"Бахрейн","OM":"Оман","JO":"Иордания","LB":"Ливан","EG":"Египет",
         "MA":"Марокко","TN":"Тунис","ZA":"ЮАР","NG":"Нигерия","KE":"Кения","GH":"Гана",
         "ET":"Эфиопия","PK":"Пакистан","BD":"Бангладеш","LK":"Шри-Ланка","NP":"Непал",
         "TH":"Таиланд","VN":"Вьетнам","MY":"Малайзия","ID":"Индонезия","PH":"Филиппины",
         "TW":"Тайвань","KH":"Камбоджа","LA":"Лаос","MM":"Мьянма","MN":"Монголия",
         "NZ":"Новая Зеландия","MX":"Мексика","CL":"Чили","CO":"Колумбия","PE":"Перу",
         "UY":"Уругвай","EC":"Эквадор","CR":"Коста-Рика","PA":"Панама","DO":"Доминиканская Республика",
         "VE":"Венесуэла","BO":"Боливия","PY":"Парагвай","GT":"Гватемала","CU":"Куба","JM":"Ямайка",
         "UZ":"Узбекистан","KG":"Кыргызстан","TJ":"Таджикистан","TM":"Туркменистан","AF":"Афганистан",
         "IQ":"Ирак","IR":"Иран","SY":"Сирия","YE":"Йемен","LY":"Ливия","DZ":"Алжир","SD":"Судан",
         "TZ":"Танзания","UG":"Уганда","SN":"Сенегал","CM":"Камерун","CI":"Кот-д’Ивуар",
         "AO":"Ангола","ZM":"Замбия","ZW":"Зимбабве","MU":"Маврикий","SC":"Сейшелы","FJ":"Фиджи",
         "PR":"Пуэрто-Рико","GI":"Гибралтар","IM":"Остров Мэн","JE":"Джерси","GG":"Гернси"}

def host_from_uri(uri):
    try:
        p = urlsplit(uri)
        if p.scheme.lower() == "vmess":
            token = (p.netloc or p.path).strip("/")
            raw = base64.b64decode(token + "=" * (-len(token) % 4))
            import json
            obj = json.loads(raw.decode("utf-8", "ignore"))
            return str(obj.get("add", "")).strip("[]")
        return p.hostname or ""
    except Exception:
        return ""

def endpoint_from_uri(uri):
    """Return (host, port) for TCP reachability checks."""
    try:
        p = urlsplit(uri)
        if p.scheme.lower() == "vmess":
            token = (p.netloc or p.path).strip("/")
            raw = base64.b64decode(token + "=" * (-len(token) % 4))
            import json
            obj = json.loads(raw.decode("utf-8", "ignore"))
            return str(obj.get("add", "")).strip("[]"), int(obj.get("port", 0))
        host = p.hostname or ""
        port = p.port
        if port is None and p.scheme.lower() in ("hysteria2", "hy2", "tuic"):
            port = 443
        return host, int(port or 0)
    except Exception:
        return "", 0


def _decode_b64(value):
    value = value.strip()
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return base64.b64decode(value + "=" * (-len(value) % 4))


def xray_outbound(uri):
    """Translate common share links into a one-server Xray outbound.
    Unsupported schemes/transports are intentionally rejected, not passed through untested.
    """
    p = urlsplit(uri)
    scheme = p.scheme.lower()
    q = parse_qs(p.query)
    def first(key, default=""):
        return q.get(key, [default])[0]

    if scheme == "vmess":
        token = (p.netloc or p.path).strip("/")
        obj = json.loads(_decode_b64(token).decode("utf-8", "replace"))
        host = str(obj.get("add", "")).strip("[]")
        port = int(obj.get("port", 0))
        user = {"id": str(obj.get("id", "")), "alterId": int(obj.get("aid", 0) or 0),
                "security": str(obj.get("scy") or "auto")}
        protocol = "vmess"
        network = str(obj.get("net") or "tcp").lower()
        tls_on = str(obj.get("tls", "")).lower() in ("tls", "true", "1")
        sni = str(obj.get("sni") or obj.get("host") or host)
        fp = str(obj.get("fp") or "")
        path = str(obj.get("path") or "/")
        ws_host = str(obj.get("host") or "")
        flow = ""
        encryption = ""
    elif scheme in ("vless", "trojan"):
        host = p.hostname or ""
        port = int(p.port or 0)
        userinfo = unquote(p.username or "")
        network = (first("type", first("network", "tcp")) or "tcp").lower()
        security = first("security", "")
        tls_on = security == "tls"
        sni = first("sni", first("serverName", first("host", host)))
        fp = first("fp", "")
        path = first("path", "/")
        ws_host = first("host", "")
        flow = first("flow", "")
        encryption = first("encryption", "none")
        if scheme == "vless":
            protocol = "vless"
            user = {"id": userinfo, "encryption": encryption}
            if flow:
                user["flow"] = flow
        else:
            protocol = "trojan"
            user = {"password": userinfo}
        if security == "reality":
            tls_on = False
    elif scheme == "ss":
        # SIP002: method:password may be base64 encoded in userinfo.
        host = p.hostname or ""
        port = int(p.port or 0)
        userinfo = p.username or ""
        decoded = _decode_b64(unquote(userinfo)).decode("utf-8", "replace") if userinfo else ""
        if ":" not in decoded and "@" not in (p.netloc or ""):
            # Legacy whole-link base64 form.
            decoded_link = _decode_b64((p.netloc or p.path).split("#", 1)[0]).decode("utf-8", "replace")
            if "@" not in decoded_link:
                raise ValueError("Invalid Shadowsocks URI")
            auth, endpoint = decoded_link.rsplit("@", 1)
            method, password = auth.split(":", 1)
            if ":" in endpoint:
                host, port_text = endpoint.rsplit(":", 1)
                port = int(port_text)
        else:
            if ":" not in decoded:
                raise ValueError("Invalid Shadowsocks credentials")
            method, password = decoded.split(":", 1)
        protocol = "shadowsocks"
        user = {"address": host, "port": port, "method": method, "password": password}
        network = "tcp"
        tls_on = False
        sni = fp = path = ws_host = flow = ""
        security = ""
    else:
        raise ValueError(f"Unsupported protocol for active test: {scheme}")

    if not host or not port:
        raise ValueError("Missing server host/port")

    settings = {}
    if protocol == "vless":
        settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    elif protocol == "vmess":
        settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    elif protocol == "trojan":
        settings = {"servers": [{"address": host, "port": port, **user}]}
    else:
        settings = {"servers": [user]}

    outbound = {"tag": "proxy", "protocol": protocol, "settings": settings}
    stream = {"network": network}
    if protocol != "shadowsocks":
        if security == "reality":
            reality = {"serverName": sni or host, "fingerprint": fp or "chrome",
                       "publicKey": first("pbk", ""), "shortId": first("sid", ""),
                       "spiderX": first("spx", "/")}
            if not reality["publicKey"]:
                raise ValueError("Reality link is missing pbk")
            stream["security"] = "reality"
            stream["realitySettings"] = reality
        elif tls_on:
            tls = {"serverName": sni or host, "allowInsecure": first("allowInsecure", "0") in ("1", "true")}
            if fp:
                tls["fingerprint"] = fp
            alpn = first("alpn", "")
            if alpn:
                tls["alpn"] = [x for x in alpn.split(",") if x]
            stream["security"] = "tls"
            stream["tlsSettings"] = tls

        if network == "ws":
            ws = {"path": path or "/"}
            if ws_host:
                ws["headers"] = {"Host": ws_host}
            stream["wsSettings"] = ws
        elif network == "grpc":
            stream["grpcSettings"] = {"serviceName": first("serviceName", path.lstrip("/"))}
        elif network in ("xhttp", "splithttp"):
            stream["network"] = "xhttp"
            stream["xhttpSettings"] = {"path": path or "/", "host": ws_host}
        elif network == "tcp":
            header_type = first("headerType", "none")
            if header_type == "http":
                stream["tcpSettings"] = {"header": {"type": "http", "request": {"path": [path or "/"], "headers": {"Host": [ws_host] if ws_host else []}}}}
        elif network not in ("httpupgrade",):
            raise ValueError(f"Unsupported Xray transport: {network}")
        if network == "httpupgrade":
            stream["network"] = "httpupgrade"
            stream["httpupgradeSettings"] = {"path": path or "/", "host": ws_host}
    outbound["streamSettings"] = stream
    return {"log": {"loglevel": "error"},
            "inbounds": [{"listen": "127.0.0.1", "port": 0, "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [outbound]}


def active_vpn_test(uri, timeout=12):
    """Pass an HTTPS request through an actual Xray tunnel and require a public exit IP."""
    xray = os.environ.get("XRAY_BIN", "xray")
    if not shutil.which(xray):
        return False, "Xray binary is not installed"
    try:
        config = xray_outbound(uri)
        # Xray supports port 0 for ephemeral inbound ports; query its allocated port via
        # a reserved local port instead to keep the SOCKS endpoint deterministic.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            socks_port = sock.getsockname()[1]
        config["inbounds"][0]["port"] = socks_port
        with tempfile.TemporaryDirectory(prefix="mimic-xray-") as temp:
            config_path = Path(temp) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            proc = subprocess.Popen([xray, "run", "-c", str(config_path)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 4
                connected = False
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        return False, "Xray exited during startup"
                    try:
                        with socket.create_connection(("127.0.0.1", socks_port), timeout=0.25):
                            connected = True
                            break
                    except OSError:
                        time.sleep(0.1)
                if not connected:
                    return False, "Local SOCKS proxy did not start"
                urls = ["https://api.ipify.org", "https://www.cloudflare.com/cdn-cgi/trace"]
                for url in urls:
                    try:
                        result = subprocess.run(
                            ["curl", "-fsS", "--socks5-hostname", f"127.0.0.1:{socks_port}",
                             "--connect-timeout", "5", "--max-time", str(timeout), url],
                            capture_output=True, text=True, timeout=timeout + 2)
                        body = result.stdout.strip()
                        if result.returncode == 0 and body:
                            if url.endswith("/trace"):
                                match = re.search(r"(?m)^ip=(\d{1,3}(?:\.\d{1,3}){3})$", body)
                                if match:
                                    return True, match.group(1)
                            elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", body):
                                return True, body
                    except (subprocess.TimeoutExpired, OSError):
                        pass
                return False, "HTTPS request through VPN tunnel failed"
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
    except Exception as exc:
        return False, str(exc)


def filter_reachable(entries):
    """Keep only entries that complete a real VPN tunnel and HTTPS request."""
    if not entries:
        return [], 0, 0
    results = [False] * len(entries)
    unsupported = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(active_vpn_test, uri): i for i, (_, uri) in enumerate(entries)}
        for future in concurrent.futures.as_completed(futures):
            i = futures[future]
            try:
                ok, detail = future.result()
                results[i] = ok
                if not ok and ("Unsupported protocol" in detail or "Unsupported Xray transport" in detail):
                    unsupported += 1
            except Exception:
                results[i] = False
    kept = [entry for i, entry in enumerate(entries) if results[i]]
    return kept, len(entries) - len(kept), unsupported


def country_from_tag(uri):
    try:
        tag = unquote(urlsplit(uri).fragment)
    except Exception:
        tag = ""
    upper = tag.upper()
    for flag in FLAG_RE.findall(tag):
        code = "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in flag)
        if code in COUNTRY_NAMES:
            return COUNTRY_NAMES[code]
    for code, name in COUNTRY_NAMES.items():
        if re.search(rf"(?<![A-Z]){re.escape(code)}(?![A-Z])", upper):
            return name
    aliases = {
        "UNITED STATES":"США","AMERICA":"США","GERMANY":"Германия","NETHERLANDS":"Нидерланды",
        "HOLLAND":"Нидерланды","FRANCE":"Франция","UNITED KINGDOM":"Великобритания",
        "ENGLAND":"Великобритания","SINGAPORE":"Сингапур","TURKEY":"Турция","JAPAN":"Япония",
        "RUSSIA":"Россия","BELARUS":"Беларусь","POLAND":"Польша","FINLAND":"Финляндия",
        "SWEDEN":"Швеция","CANADA":"Канада",
    }
    for needle, name in aliases.items():
        if needle in upper:
            return name
    for name in COUNTRY_NAMES.values():
        if name.upper() in upper:
            return name
    return ""

def geolocate_hosts(hosts):
    import ipaddress
    import json
    import socket
    host_ips = {}
    all_ips = set()
    for host in hosts:
        try:
            ip = str(ipaddress.ip_address(host))
        except ValueError:
            try:
                answers = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
                ip = answers[0][4][0]
            except Exception:
                continue
        try:
            parsed = ipaddress.ip_address(ip)
            if not parsed.is_global:
                continue
        except ValueError:
            continue
        host_ips[host] = ip
        all_ips.add(ip)

    ip_countries = {}
    ip_list = sorted(all_ips)
    for offset in range(0, len(ip_list), 100):
        batch = ip_list[offset:offset+100]
        if not batch:
            continue
        payload = json.dumps([{"query": ip} for ip in batch]).encode("utf-8")
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,query,countryCode",
            data=payload,
            headers={"Content-Type":"application/json","User-Agent":"MIMIC-VPN-Subscription/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as response:
                results = json.loads(response.read().decode("utf-8"))
            for item in results:
                if item.get("status") == "success":
                    ip_countries[item.get("query","")] = COUNTRY_NAMES.get(item.get("countryCode",""), "")
        except Exception as exc:
            print(f"Предупреждение: геолокация IP временно недоступна: {exc}", file=sys.stderr)
    return {host: ip_countries.get(ip, "") for host, ip in host_ips.items()}

def flag_for_country(country):
    # HAPP displays a flag icon only when the first emoji in the server name is a flag.
    # Derive flags only for countries explicitly recognized by the source metadata.
    for code, name in FLAGS.items():
        if name == country and code != "UK":
            first = chr(0x1F1E6 + ord(code[0]) - ord("A"))
            second = chr(0x1F1E6 + ord(code[1]) - ord("A"))
            return first + second
    return ""

def canonical(uri):
    p = urlsplit(uri)
    # Ignore only the display fragment when checking duplicates.
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path, p.query, ""))

def main():
    all_uris = []
    source_counts = []
    source_errors = []
    for name, url in SOURCES:
        try:
            data = fetch(name, url)
            uris = extract_uris(data)
            if not uris:
                raise RuntimeError("загрузка прошла, но VPN-ссылки не найдены")
            source_counts.append((name, len(uris)))
            all_uris.extend(uris)
            print(f"{name}: получено ссылок: {len(uris)}")
        except Exception as exc:
            # A single provider can change its response format or temporarily fail.
            # Keep building from the remaining providers; fail only if no usable
            # source remains, so a bad optional source cannot block all updates.
            source_errors.append((name, str(exc)))
            print(f"ПРЕДУПРЕЖДЕНИЕ: {name}: {exc}; источник пропущен", file=sys.stderr)

    if not all_uris:
        details = "; ".join(f"{name}: {error}" for name, error in source_errors)
        raise RuntimeError(
            "Ни один источник не предоставил VPN-ссылки; прежняя подписка сохранится. "
            + details
        )

    unique = {}
    for uri in all_uris:
        unique.setdefault(canonical(uri), uri)
    raw_entries = list(unique.values())
    tagged = {uri: country_from_tag(uri) for uri in raw_entries}
    hosts = {host_from_uri(uri) for uri in raw_entries if not tagged[uri]}
    geo = geolocate_hosts({h for h in hosts if h})
    entries = []
    skipped = 0
    for uri in raw_entries:
        country = tagged[uri] or geo.get(host_from_uri(uri), "")
        if not country:
            skipped += 1
            continue
        entries.append((country, uri))
    entries.sort(key=lambda item: (item[0], canonical(item[1])))

    entries, active_failed, unsupported = filter_reachable(entries)
    if not entries:
        raise RuntimeError("Ни один сервер не прошёл реальную проверку VPN-туннеля; прежняя подписка сохранится")

    counts = {}
    output = ["#profile-title: MIMICVPN"]
    for country, uri in entries:
        number = counts.get(country, 0)
        counts[country] = number + 1
        label = country if number == 0 else f"{country} {number}"
        flag = flag_for_country(country)
        server_name = f"{flag} {label}" if flag else label
        p = urlsplit(uri)
        output.append(urlunsplit((p.scheme, p.netloc, p.path, p.query, quote(server_name, safe=""))))

    if len(output) <= 1:
        raise RuntimeError("Не удалось определить страны ни для одного сервера; прежняя подписка сохранится")
    OUT.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(f"Готово: {len(output)-1} серверов прошли реальный VPN-тест; не прошли тест: {active_failed}; неподдерживаемые форматы/транспорты: {unsupported}; исключено без страны: {skipped}")
    print("Проверка включает запуск Xray, установление туннеля и HTTPS-запрос через SOCKS-прокси с проверкой внешнего IP.")
    for name, count in source_counts:
        print(f"{name}: {count}")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        sys.exit(1)
