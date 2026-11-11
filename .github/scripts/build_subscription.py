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

def country_from_uri(uri):
    try:
        tag = unquote(urlsplit(uri).fragment)
    except Exception:
        tag = ""
    upper = tag.upper()
    # Emoji flag pairs.
    for flag in FLAG_RE.findall(tag):
        code = "".join(chr(ord(c) - 0x1F1E6 + ord("A")) for c in flag)
        if code in FLAGS:
            return FLAGS[code]
    # Common country codes/names in source tags.
    for code, name in sorted(FLAGS.items(), key=lambda x: -len(x[0])):
        if re.search(rf"(?<![A-Z]){re.escape(code)}(?![A-Z])", upper):
            return name
    aliases = {
        "UNITED STATES":"США", "AMERICA":"США", "GERMANY":"Германия",
        "NETHERLANDS":"Нидерланды", "HOLLAND":"Нидерланды", "FRANCE":"Франция",
        "UNITED KINGDOM":"Великобритания", "ENGLAND":"Великобритания",
        "SINGAPORE":"Сингапур", "TURKEY":"Турция", "JAPAN":"Япония",
        "RUSSIA":"Россия", "BELARUS":"Беларусь", "POLAND":"Польша",
        "FINLAND":"Финляндия", "SWEDEN":"Швеция", "CANADA":"Канада",
    }
    for needle, name in aliases.items():
        if needle in upper:
            return name
    # Already-localized country names in a tag.
    for name in set(FLAGS.values()):
        if name.upper() in upper:
            return name
    return "Неизвестная страна"

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
    entries = [(country_from_uri(uri), uri) for uri in unique.values()]
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

    if not output:
        raise RuntimeError("Итоговый список пуст; прежняя подписка сохранится")
    OUT.write_text("\n".join(output) + "\n", encoding="utf-8")
    print(f"Готово: {len(output)} уникальных серверов из {sum(n for _, n in source_counts)} записей")
    for name, count in source_counts:
        print(f"{name}: {count}")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ОШИБКА: {exc}", file=sys.stderr)
        sys.exit(1)
