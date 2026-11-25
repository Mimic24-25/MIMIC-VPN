#!/usr/bin/env python3
"""Build a single MIMIC VPN subscription from configured sources.

All available sources are fetched before the output file is replaced.
Private Wepogp subscription URLs are read only from GitHub Secrets.
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
import urllib.error
from pathlib import Path
from urllib.parse import quote, unquote, urlencode, urlsplit, urlunsplit, parse_qs, parse_qsl

SOURCES = [
    ("Wepogp-1", os.environ.get("WEPOGP_SOURCE_1_URL", "").strip()),
    ("VlessForU", "https://sub.vlessfo.ru/vlessforu/working_configs.txt"),
    ("Wepogp-2", os.environ.get("WEPOGP_SOURCE_2_URL", "").strip()),
    ("FreeVPN-Cracks", "https://raw.githubusercontent.com/gooseteam-hackers/freevpn-cracks/refs/heads/main/subscription_auto.txt"),
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
        raise RuntimeError(f"Не задан GitHub Secret для источника {name}")
    req = urllib.request.Request(url, headers={"User-Agent":"MIMIC-VPN-Subscription/1.0"})
    last_error = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=35) as response:
                raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise RuntimeError(f"{name}: источник больше 8 МБ")
            return raw.decode("utf-8-sig", errors="replace")
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in (408, 429, 500, 502, 503, 504) or attempt == 3:
                raise
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt == 3:
                raise
        time.sleep(min(2 ** attempt, 8))
    raise RuntimeError(f"{name}: загрузка не удалась после повторных попыток: {last_error}")

def decode_payload(text):
    text = text.strip()
    if any(s in text.lower() for s in SCHEMES):
        return text
    compact = re.sub(r"\s+", "", text)
    if compact and re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
        try:
            decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", "ignore")
            if any(s in decoded.lower() for s in SCHEMES) or decoded.lstrip().startswith(("{", "[")):
                return decoded
        except Exception:
            pass
    return text

def extract_uris(payload):
    payload = decode_payload(payload)
    found = []
    try:
        parsed = json.loads(payload)
    except Exception:
        parsed = None

    # Providers may publish either a single Xray profile or a JSON array
    # of profiles. Normalize both into ordinary share links.
    profiles = parsed if isinstance(parsed, list) else [parsed]
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get("outbounds"), list):
            continue
        for outbound in profile["outbounds"]:
            if not isinstance(outbound, dict):
                continue
            protocol = str(outbound.get("protocol", "")).lower()
            settings = outbound.get("settings", {})
            stream = outbound.get("streamSettings", {})
            if protocol not in ("vless", "trojan"):
                continue
            servers = settings.get("vnext", []) if protocol == "vless" else settings.get("servers", [])
            for server in servers:
                host = str(server.get("address", "")).strip()
                port = int(server.get("port", 0) or 0)
                users = server.get("users", []) if protocol == "vless" else [server]
                for user in users:
                    credential = str(user.get("id", "") if protocol == "vless" else user.get("password", ""))
                    if not host or not port or not credential:
                        continue
                    params = {}
                    network = str(stream.get("network", "tcp"))
                    if network:
                        params["type"] = network
                    if stream.get("security"):
                        params["security"] = stream["security"]
                    tls = stream.get("tlsSettings", {})
                    reality = stream.get("realitySettings", {})
                    if tls.get("serverName") or reality.get("serverName"):
                        params["sni"] = tls.get("serverName") or reality.get("serverName")
                    if tls.get("fingerprint") or reality.get("fingerprint"):
                        params["fp"] = tls.get("fingerprint") or reality.get("fingerprint")
                    if tls.get("alpn"):
                        params["alpn"] = ",".join(tls["alpn"])
                    if reality.get("publicKey"):
                        params["pbk"] = reality["publicKey"]
                    if reality.get("shortId"):
                        params["sid"] = reality["shortId"]
                    transport = (stream.get("xhttpSettings") or stream.get("wsSettings")
                                 or stream.get("grpcSettings") or {})
                    if transport.get("path"):
                        params["path"] = transport["path"]
                    if transport.get("host"):
                        params["host"] = transport["host"]
                    if transport.get("serviceName"):
                        params["serviceName"] = transport["serviceName"]
                    if transport.get("mode"):
                        params["mode"] = transport["mode"]
                    if transport.get("extra"):
                        extra = json.dumps(transport["extra"], separators=(",", ":")).encode("utf-8")
                        params["extra"] = base64.urlsafe_b64encode(extra).decode("ascii").rstrip("=")
                    if user.get("flow"):
                        params["flow"] = user["flow"]
                    if user.get("encryption"):
                        params["encryption"] = user["encryption"]
                    tag = outbound.get("tag") or profile.get("remarks") or profile.get("name") or "Xray server"
                    fragment = quote(str(tag), safe="")
                    found.append(f"{protocol}://{quote(credential, safe='')}@{host}:{port}?{urlencode(params)}#{fragment}")

    if found:
        return found

    for line in payload.splitlines():
        line = line.strip().strip("\ufeff")
        if not line or line.startswith(("#", ";")):
            continue
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
        # VMess stores TLS in its Base64 JSON, not in the URI query.
        security = "tls" if tls_on else ""
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

    # Xray's current name for the TCP transport is "raw".
    if network == "raw":
        network = "tcp"

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
            tls = {"serverName": sni or host, "allowInsecure": False, "minVersion": "1.2", "maxVersion": "1.3"}
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
            xhttp = {"path": path or "/", "host": ws_host}
            mode = first("mode", "")
            if mode:
                xhttp["mode"] = mode
            encoded_extra = first("extra", "")
            if encoded_extra:
                try:
                    xhttp["extra"] = json.loads(_decode_b64(encoded_extra).decode("utf-8"))
                except Exception as exc:
                    raise ValueError(f"Invalid XHTTP extra settings: {exc}")
            stream["xhttpSettings"] = xhttp
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


def enforce_transport_security(uri):
    """Reject profiles that do not encrypt the client-to-proxy connection safely."""
    p = urlsplit(uri)
    scheme = p.scheme.lower()
    q = parse_qs(p.query)
    security = q.get("security", [""])[0].lower()

    if scheme == "vless":
        if security not in ("reality", "tls"):
            raise ValueError("Rejected by privacy policy: VLESS without TLS/REALITY")
        if q.get("allowInsecure", ["0"])[0].lower() in ("1", "true", "yes"):
            raise ValueError("Rejected by privacy policy: insecure TLS certificate validation")
        if security == "reality" and not q.get("pbk", [""])[0]:
            raise ValueError("Rejected by privacy policy: REALITY public key is missing")
        return

    if scheme == "vmess":
        token = (p.netloc or p.path).strip("/")
        obj = json.loads(_decode_b64(token).decode("utf-8", "replace"))
        if str(obj.get("tls", "")).lower() not in ("tls", "true", "1"):
            raise ValueError("Rejected by privacy policy: VMess without TLS")
        return

    if scheme == "trojan":
        if security != "tls":
            raise ValueError("Rejected by privacy policy: Trojan without TLS")
        if q.get("allowInsecure", ["0"])[0].lower() in ("1", "true", "yes"):
            raise ValueError("Rejected by privacy policy: insecure TLS certificate validation")
        return

    if scheme == "ss":
        # Only authenticated-encryption ciphers; reject legacy stream/CFB ciphers.
        userinfo = p.username or ""
        decoded = _decode_b64(unquote(userinfo)).decode("utf-8", "replace") if userinfo else ""
        method = ""
        if ":" in decoded:
            method = decoded.split(":", 1)[0].lower()
        else:
            legacy = _decode_b64((p.netloc or p.path).split("#", 1)[0]).decode("utf-8", "replace")
            if "@" in legacy and ":" in legacy.split("@", 1)[0]:
                method = legacy.split("@", 1)[0].split(":", 1)[0].lower()
        allowed = {
            "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        }
        if method not in allowed:
            raise ValueError("Rejected by privacy policy: Shadowsocks cipher is not an approved AEAD cipher")
        return

    raise ValueError(f"Rejected by privacy policy: unsupported protocol {scheme}")


def active_vpn_test(uri, baseline_ip=None, timeout=10):
    """Require a stable VPN exit plus YouTube and Telegram HTTPS reachability."""
    xray = os.environ.get("XRAY_BIN", "xray")
    if not shutil.which(xray):
        return False, "Xray binary is not installed"
    try:
        enforce_transport_security(uri)
        config = xray_outbound(uri)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            socks_port = sock.getsockname()[1]
        config["inbounds"][0]["port"] = socks_port
        with tempfile.TemporaryDirectory(prefix="mimic-xray-") as temp:
            config_path = Path(temp) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as xray_log:
                proc = subprocess.Popen([xray, "run", "-c", str(config_path)],
                                        stdout=subprocess.DEVNULL, stderr=xray_log)

                def xray_error():
                    try:
                        xray_log.flush()
                        xray_log.seek(0)
                        return xray_log.read()[-1200:].strip().replace("\n", " ")
                    except Exception:
                        return ""

                try:
                    deadline = time.monotonic() + 5
                    connected = False
                    while time.monotonic() < deadline:
                        if proc.poll() is not None:
                            detail = xray_error()
                            return False, "Xray exited during startup" + (f": {detail}" if detail else "")
                        try:
                            with socket.create_connection(("127.0.0.1", socks_port), timeout=0.25):
                                connected = True
                                break
                        except OSError:
                            time.sleep(0.1)
                    if not connected:
                        detail = xray_error()
                        return False, "Local SOCKS proxy did not start" + (f": {detail}" if detail else "")

                    proxy_args = ["--socks5-hostname", f"127.0.0.1:{socks_port}",
                                  "--connect-timeout", "5", "--max-time", str(timeout),
                                  "--location", "--max-redirs", "5"]

                    ip_urls = [
                        "https://api.ipify.org",
                        "https://checkip.amazonaws.com",
                        "https://ipv4.icanhazip.com",
                    ]

                    def check_ip(url):
                        try:
                            result = subprocess.run(
                                ["curl", "-4", "-fsS", "--request", "GET", *proxy_args, url],
                                capture_output=True, text=True, timeout=timeout + 2)
                            if result.returncode != 0:
                                reason = (result.stderr or f"curl exit {result.returncode}").strip()
                                return None, reason[:180]
                            match = re.search(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])",
                                              result.stdout.strip())
                            if not match:
                                return None, "provider returned no IPv4 address"
                            import ipaddress
                            ip = ipaddress.ip_address(match.group(0))
                            if ip.version != 4 or not ip.is_global:
                                return None, "provider returned a non-public IPv4 address"
                            return str(ip), ""
                        except subprocess.TimeoutExpired:
                            return None, "curl request timed out"
                        except OSError as exc:
                            return None, f"curl execution failed: {exc}"

                    def probe_http(url):
                        """Return final HTTP status; any TLS/transport error is a failure."""
                        try:
                            result = subprocess.run(
                                ["curl", "-4", "-sS", "--request", "GET", *proxy_args,
                                 "--output", os.devnull, "--write-out", "%{http_code}", url],
                                capture_output=True, text=True, timeout=timeout + 2)
                            if result.returncode != 0:
                                reason = (result.stderr or f"curl exit {result.returncode}").strip()
                                return None, reason[:160]
                            try:
                                status = int(result.stdout.strip())
                            except ValueError:
                                return None, "no HTTP status received"
                            return status, ""
                        except subprocess.TimeoutExpired:
                            return None, "request timed out"
                        except OSError as exc:
                            return None, f"curl execution failed: {exc}"

                    def check_services():
                        # YouTube's generate_204 endpoint is used by its clients as a
                        # lightweight connectivity probe. A normal homepage response
                        # is accepted as a fallback when the probe is redirected.
                        yt_status, yt_error = probe_http("https://www.youtube.com/generate_204")
                        youtube_ok = yt_status == 204
                        if not youtube_ok:
                            home_status, home_error = probe_http("https://www.youtube.com/")
                            youtube_ok = home_status is not None and 200 <= home_status < 400
                            if not youtube_ok:
                                reason = yt_error or f"generate_204 returned HTTP {yt_status}"
                                reason += "; homepage: " + (home_error or f"HTTP {home_status}")
                                return False, "YouTube unavailable (" + reason + ")"

                        # Telegram Web is the user-facing web client. The public
                        # Telegram site is a fallback reachability signal, not a
                        # guarantee that native-app messaging works.
                        tg_status, tg_error = probe_http("https://web.telegram.org/a/")
                        telegram_ok = tg_status is not None and 200 <= tg_status < 400
                        if not telegram_ok:
                            site_status, site_error = probe_http("https://telegram.org/")
                            telegram_ok = site_status is not None and 200 <= site_status < 400
                            if not telegram_ok:
                                reason = tg_error or f"web.telegram.org returned HTTP {tg_status}"
                                reason += "; telegram.org: " + (site_error or f"HTTP {site_status}")
                                return False, "Telegram unavailable (" + reason + ")"
                        return True, f"YouTube OK (HTTP {yt_status if yt_status is not None else 'fallback'}); Telegram OK (HTTP {tg_status if tg_status is not None else 'fallback'})"

                    def verify_round():
                        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as checks:
                            observed = list(checks.map(check_ip, ip_urls))
                        valid = [ip for ip, _ in observed if ip]
                        if len(valid) != 3:
                            reasons = "; ".join(
                                f"{ip_urls[i].split('/')[2]}: {reason}"
                                for i, (ip, reason) in enumerate(observed) if not ip
                            )
                            return None, f"Only {len(valid)}/3 independent HTTPS IP checks succeeded; all 3 are required" + (f" ({reasons})" if reasons else "")
                        if len(set(valid)) != 1:
                            return None, "HTTPS providers reported inconsistent VPN exit IPs: " + ", ".join(valid)
                        services_ok, services_detail = check_services()
                        if not services_ok:
                            return None, services_detail
                        return valid[0], services_detail

                    # Require two consecutive rounds: all three IP providers must
                    # agree, and both target services must answer through this proxy.
                    first_ip, first_detail = verify_round()
                    if not first_ip:
                        return False, first_detail
                    time.sleep(1)
                    second_ip, second_detail = verify_round()
                    if not second_ip:
                        return False, "Second stability check failed: " + second_detail
                    if first_ip != second_ip:
                        return False, f"VPN exit IP changed between stability checks: {first_ip} -> {second_ip}"
                    if baseline_ip and second_ip == baseline_ip:
                        return False, "Exit IP matches GitHub runner direct IP; VPN tunnel not confirmed"
                    print(f"Сервисы через VPN: {second_detail}; exit IP: {second_ip}")
                    return True, f"{second_ip}; {second_detail}"
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
    """Keep only entries that prove a distinct VPN exit via multiple HTTPS providers."""
    if not entries:
        return [], 0, 0

    # A proxy response through the runner's normal connection is not a VPN.
    try:
        baseline = subprocess.run(
            ["curl", "-4", "-fsS", "--request", "GET", "--connect-timeout", "5", "--max-time", "10",
             "https://api.ipify.org"],
            capture_output=True, text=True, timeout=12)
        baseline_ip = baseline.stdout.strip()
        import ipaddress
        parsed_baseline = ipaddress.ip_address(baseline_ip)
        if baseline.returncode != 0 or parsed_baseline.version != 4 or not parsed_baseline.is_global:
            raise ValueError("invalid direct public IP")
    except Exception as exc:
        raise RuntimeError(f"Не удалось получить контрольный внешний IP GitHub runner: {exc}")

    print("Контрольный IP GitHub runner получен; проверяется отдельный VPN exit IP.")
    results = [False] * len(entries)
    unsupported = 0
    failure_reasons = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(active_vpn_test, uri, baseline_ip): i for i, (_, uri) in enumerate(entries)}
        for future in concurrent.futures.as_completed(futures):
            i = futures[future]
            try:
                ok, detail = future.result()
                results[i] = ok
                if not ok:
                    failure_reasons[detail] = failure_reasons.get(detail, 0) + 1
                    if "Unsupported protocol" in detail or "Unsupported Xray transport" in detail:
                        unsupported += 1
            except Exception as exc:
                results[i] = False
                reason = f"Unexpected test error: {exc}"
                failure_reasons[reason] = failure_reasons.get(reason, 0) + 1
    for reason, count in sorted(failure_reasons.items(), key=lambda item: (-item[1], item[0]))[:12]:
        print(f"Причина исключения ({count}): {reason}")
    kept = [entry for i, entry in enumerate(entries) if results[i]]
    return kept, len(entries) - len(kept), unsupported


def endpoint_latency_ms(uri):
    """Measure HTTPS GET response latency through the tested Xray VPN tunnel."""
    xray = os.environ.get("XRAY_BIN", "xray")
    if not shutil.which(xray):
        return float("inf")
    try:
        enforce_transport_security(uri)
        config = xray_outbound(uri)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            socks_port = sock.getsockname()[1]
        config["inbounds"][0]["port"] = socks_port
        with tempfile.TemporaryDirectory(prefix="mimic-xray-rank-") as temp:
            config_path = Path(temp) / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            proc = subprocess.Popen([xray, "run", "-c", str(config_path)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        return float("inf")
                    try:
                        with socket.create_connection(("127.0.0.1", socks_port), timeout=0.25):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    return float("inf")

                started = time.perf_counter()
                result = subprocess.run(
                    ["curl", "-4", "-fsS", "--request", "GET",
                     "--socks5-hostname", f"127.0.0.1:{socks_port}",
                     "--connect-timeout", "5", "--max-time", "8",
                     "https://api.ipify.org"],
                    capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    return float("inf")
                import ipaddress
                ip = ipaddress.ip_address(result.stdout.strip())
                if ip.version != 4 or not ip.is_global:
                    return float("inf")
                return (time.perf_counter() - started) * 1000.0
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
    except Exception:
        return float("inf")


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

def normalize_happ_xhttp_uri(uri):
    """Remove non-portable XHTTP extra before testing, so tests match published links."""
    p = urlsplit(uri)
    params = parse_qsl(p.query, keep_blank_values=True)
    is_xhttp = any(key.lower() == "type" and value.lower() in ("xhttp", "splithttp")
                   for key, value in params)
    if not is_xhttp:
        return uri
    filtered = [(key, value) for key, value in params if key.lower() != "extra"]
    if len(filtered) == len(params):
        return uri
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(filtered), p.fragment))


def canonical(uri):
    p = urlsplit(uri)
    # Ignore only the display fragment when checking duplicates.
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path, p.query, ""))

def main():
    all_uris = []
    source_counts = {}
    source_errors = []
    source_uris = {name: set() for name, _ in SOURCES}
    source_map = {}
    for name, url in SOURCES:
        try:
            data = fetch(name, url)
            uris = extract_uris(data)
            if not uris:
                raise RuntimeError("загрузка прошла, но VPN-ссылки не найдены")
            source_counts[name] = len(uris)
            for uri in uris:
                key = canonical(uri)
                source_uris[name].add(key)
                source_map.setdefault(key, set()).add(name)
            all_uris.extend(uris)
            print(f"{name}: получено ссылок: {len(uris)}")
        except Exception as exc:
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
    raw_entries = [normalize_happ_xhttp_uri(uri) for uri in unique.values()]
    # Active VPN tests now exercise the exact XHTTP links that HAPP will receive.
    unique_normalized = {}
    for uri in raw_entries:
        unique_normalized.setdefault(canonical(uri), uri)
    raw_entries = list(unique_normalized.values())
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

    # Keep a per-provider view even when the same URI appears in multiple sources.
    tested_keys = {canonical(uri) for _, uri in entries}
    entries, active_failed, unsupported = filter_reachable(entries)
    passed_keys = {canonical(uri) for _, uri in entries}

    print("\nСТАТИСТИКА ПО ИСТОЧНИКАМ (дубли учитываются у каждого поставщика):")
    summary_lines = [
        "## Статистика VPN-источников",
        "",
        "| Источник | Получено ссылок | Уникальных конфигов | Проверено | Прошло VPN-тест | Не прошло | Доля успеха |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, _ in SOURCES:
        keys = source_uris[name]
        tested = len(keys & tested_keys)
        passed = len(keys & passed_keys)
        failed = tested - passed
        fetched = source_counts.get(name, 0)
        unique_count = len(keys)
        rate = f"{passed / tested * 100:.1f}%" if tested else "—"
        error = next((message for source, message in source_errors if source == name), "")
        suffix = f" (источник пропущен: {error})" if error else ""
        print(f"{name}: получено {fetched}; уникальных {unique_count}; проверено {tested}; прошло {passed}; не прошло {failed}; успех {rate}{suffix}")
        summary_lines.append(f"| {name} | {fetched} | {unique_count} | {tested} | {passed} | {failed} | {rate} |")
    untested_country = len(raw_entries) - len(tested_keys)
    summary_lines.extend(["", f"Не определена страна: {untested_country}.", "",
        "Примечание: одинаковые конфиги, найденные в нескольких источниках, учитываются в статистике каждого такого источника; поэтому суммы по источникам могут быть больше общего числа уникальных конфигов.",
        "Проверка — реальный Xray/SOCKS-туннель с двумя раундами независимых HTTPS-проверок. Это не измерение пропускной способности или IP-репутации."])
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary_file:
            summary_file.write("\n".join(summary_lines) + "\n")
    if not entries:
        raise RuntimeError("Ни один сервер не прошёл реальную проверку VPN-туннеля; прежняя подписка сохранится")

    # Rank only servers that passed every active VPN check. Missing preferred
    # countries must not discard otherwise-working servers from the subscription.
    preferred_countries = ("Нидерланды", "Германия", "Финляндия", "США")
    present_countries = {country for country, _ in entries}
    winner_countries = [country for country in preferred_countries if country in present_countries]
    winner_countries.extend(sorted(present_countries - set(preferred_countries)))

    latency_ms = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        latency_futures = {pool.submit(endpoint_latency_ms, uri): uri for _, uri in entries}
        for future in concurrent.futures.as_completed(latency_futures):
            latency_ms[latency_futures[future]] = future.result()
    best_by_country = {}
    for country in winner_countries:
        candidates = [uri for item_country, uri in entries if item_country == country]
        best_by_country[country] = min(
            candidates,
            key=lambda uri: (latency_ms.get(uri, float("inf")), canonical(uri))
        )

    best_uris = set(best_by_country.values())
    ordered_entries = [
        (country, best_by_country[country], True)
        for country in winner_countries
    ]
    ordered_entries.extend(
        (country, uri, False)
        for country, uri in entries if uri not in best_uris
    )

    counts = {}
    routing_profile = {
        "Name": "MIMICVPN Secure DNS",
        "GlobalProxy": "true",
        "RemoteDNSType": "DoH",
        "RemoteDNSDomain": "https://cloudflare-dns.com/dns-query",
        "RemoteDNSIP": "1.1.1.1",
        "DomesticDNSType": "DoH",
        "DomesticDNSDomain": "https://dns.google/dns-query",
        "DomesticDNSIP": "8.8.8.8",
        "DnsHosts": {
            "cloudflare-dns.com": "1.1.1.1",
            "dns.google": "8.8.8.8"
        },
        "DirectSites": [],
        "DirectIp": [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255"
        ],
        "ProxySites": [],
        "ProxyIp": [],
        "BlockSites": [],
        "BlockIp": [],
        "DomainStrategy": "IPIfNonMatch",
        "FakeDNS": "false"
    }
    routing_payload = base64.b64encode(
        json.dumps(routing_profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    output = [
        "#profile-title: MIMICVPN",
        "#profile-update-interval: 1",
        f"happ://routing/onadd/{routing_payload}"
    ]
    for country, uri, is_best in ordered_entries:
        if is_best:
            label = f"{country} — Лучший сервер"
            counts[country] = 1
        else:
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
    for country in winner_countries:
        winner = best_by_country[country]
        measured = latency_ms.get(winner, float("inf"))
        latency_text = f"{measured:.1f} ms" if measured != float("inf") else "TCP latency unavailable"
        print(f"Лучший сервер — {country}: {latency_text}")
    print("Проверка включает запуск Xray, SOCKS-туннель, два последовательных раунда: все 3 независимые HTTPS-проверки должны успешно ответить в каждом раунде и сообщить одинаковый VPN exit IP; IP также сравнивается с прямым IP GitHub runner.")
    print(f"Всего уникальных конфигов: {len(raw_entries)}; прошли геолокацию и отправлены на активный тест: {len(tested_keys)}; без определённой страны: {untested_country}.")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        sys.exit(1)
