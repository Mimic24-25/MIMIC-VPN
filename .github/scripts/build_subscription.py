#!/usr/bin/env python3
"""Build a single MIMIC VPN subscription from three sources.

All sources must be fetched successfully before the output file is replaced.
The V2Hub URL is read only from the V2HUB_SUB_URL environment variable.
"""
import base64
import os
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

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
    for name, url in SOURCES:
        data = fetch(name, url)
        uris = extract_uris(data)
        if not uris:
            raise RuntimeError(f"{name}: загрузка прошла, но VPN-ссылки не найдены; прежняя подписка сохранится")
        source_counts.append((name, len(uris)))
        all_uris.extend(uris)

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
    print(f"Готово: {len(output)-1} серверов с определённой страной; исключено без страны или с недоступным адресом: {skipped}")
    for name, count in source_counts:
        print(f"{name}: {count}")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        sys.exit(1)
