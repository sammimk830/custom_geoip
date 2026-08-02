import ipaddress
import json
import os
import re
import urllib.request

import maxminddb


DATA_DIR = "data"
COUNTRY_MMDB_FILE = "base.mmdb"
ASN_MMDB_PREFIX = "asn-base"

os.makedirs(DATA_DIR, exist_ok=True)


def download_file(url, output_path):
    print(f"[ Download ] {url}")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"},
    )

    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            content = response.read()

        if not content:
            raise RuntimeError("下載內容為空")

        with open(output_path, "wb") as output_file:
            output_file.write(content)

        print(f"  └─ 已下載：{output_path} ({len(content):,} bytes)")
        return True

    except Exception as exc:
        print(f"  └─ 下載失敗：{exc}")
        return False


def fetch_content(source):
    if source.startswith(("http://", "https://")):
        print(f"  └─ 正在下載遠端規則：{source}")

        request = urllib.request.Request(
            source,
            headers={"User-Agent": "Mozilla/5.0"},
        )

        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read().decode(
                    "utf-8",
                    errors="ignore",
                ).splitlines()

        except Exception as exc:
            print(f"  └─ 下載失敗 {source}：{exc}")
            return []

    print(f"  └─ 正在讀取本地規則：{source}")

    if not os.path.exists(source):
        print(f"  └─ 警告：找不到本地檔案 {source}")
        return []

    try:
        with open(source, "r", encoding="utf-8") as source_file:
            return source_file.readlines()

    except Exception as exc:
        print(f"  └─ 讀取失敗 {source}：{exc}")
        return []


def clean_ip_cidr(ip_string):
    ip_string = ip_string.strip()

    try:
        if "/" not in ip_string:
            address = ipaddress.ip_address(ip_string)
            prefix = 32 if address.version == 4 else 128
            return f"{address}/{prefix}"

        return str(
            ipaddress.ip_network(
                ip_string,
                strict=False,
            )
        )

    except ValueError:
        return None


def parse_line(line):
    line = line.strip()

    if (
        not line
        or line.startswith("#")
        or line.startswith("//")
        or line.startswith("payload:")
    ):
        return None

    if " #" in line:
        line = line.split(" #", 1)[0]
    elif "//" in line and not line.startswith("http"):
        line = line.split("//", 1)[0]

    line = (
        line.strip()
        .lstrip("- ")
        .replace("'", "")
        .replace('"', "")
        .strip()
    )

    ip_part = line

    if "," in line:
        parts = [part.strip() for part in line.split(",")]

        if len(parts) < 2:
            return None

        rule_type = parts[0].upper()

        if rule_type.startswith("DOMAIN") or rule_type == "REGEXP":
            return None

        ip_part = parts[1]

    return clean_ip_cidr(ip_part)


def get_asn_number(record):
    if not isinstance(record, dict):
        return None

    asn = record.get("autonomous_system_number")

    if isinstance(asn, int) and asn > 0:
        return asn

    if isinstance(asn, str) and asn.isdigit():
        return int(asn)

    return None


def extract_asn_mmdb(mmdb_path, output_data):
    print(f"\n[ ASN MMDB ] 正在處理：{mmdb_path}")

    generated_count = 0
    skipped_count = 0

    with maxminddb.open_database(mmdb_path) as reader:
        for network, record in reader:
            asn = get_asn_number(record)

            if not asn:
                skipped_count += 1
                continue

            tag = f"as{asn}"
            output_data.setdefault(tag, set()).add(str(network))
            generated_count += 1

    print(f"  ├─ 有效 ASN CIDR：{generated_count:,}")
    print(f"  └─ 無 ASN 記錄：{skipped_count:,}")


def write_data_files(output_data):
    for tag, rules in output_data.items():
        output_path = os.path.join(DATA_DIR, tag)

        with open(output_path, "w", encoding="utf-8") as output_file:
            if rules:
                output_file.write("\n".join(sorted(rules)))
                output_file.write("\n")

        print(f"  └─ Tag [{tag}] 完成：輸出 {len(rules):,} 條")


def main():
    with open("config.json", "r", encoding="utf-8") as config_file:
        config = json.load(config_file)

    # Country MMDB 仍然下載成 base.mmdb，
    # 留俾 workflow 使用 v2fly --base 合併。
    country_mmdb_url = config.get("base_mmdb_url", "").strip()

    if country_mmdb_url:
        print("[ Country MMDB ] 正在下載基底數據庫")

        if not download_file(
            country_mmdb_url,
            COUNTRY_MMDB_FILE,
        ):
            raise RuntimeError("Country MMDB 下載失敗")

    output_data = {}

    # 處理自訂分類。
    categories = config.get("categories", {})

    for tag, category_data in categories.items():
        if tag.startswith("_"):
            continue

        print(f"\n[ Processing Category: {tag} ]")

        rules_set = set()
        exclude_set = set()

        if isinstance(category_data, dict):
            sources = (
                category_data.get("urls", [])
                + category_data.get("local_files", [])
            )
            inline_rules = category_data.get("inline_rules", [])
            exclude_rules = category_data.get("exclude_rules", [])
        elif isinstance(category_data, list):
            sources = category_data
            inline_rules = []
            exclude_rules = []
        else:
            print("  └─ 分類格式無效，已跳過")
            continue

        for exclude_line in exclude_rules:
            parsed_exclude = parse_line(exclude_line)

            if parsed_exclude:
                exclude_set.add(parsed_exclude)

        for source_item in sources:
            if isinstance(source_item, dict):
                source = source_item.get("url", "")
            else:
                source = source_item

            if not source:
                continue

            for line in fetch_content(source):
                parsed_rule = parse_line(line)

                if parsed_rule:
                    rules_set.add(parsed_rule)

        for inline_line in inline_rules:
            parsed_rule = parse_line(inline_line)

            if parsed_rule:
                rules_set.add(parsed_rule)

        output_data[tag] = rules_set - exclude_set

    # ASN MMDB 唔會交俾 v2fly --base，
    # 而係拆成 data/as13335、data/as4515 等普通 GeoIP tag。
    asn_mmdb_urls = config.get("asn_mmdb_urls", [])

    if isinstance(asn_mmdb_urls, str):
        asn_mmdb_urls = [asn_mmdb_urls]

    for index, asn_mmdb_url in enumerate(asn_mmdb_urls, start=1):
        asn_mmdb_url = asn_mmdb_url.strip()

        if not asn_mmdb_url:
            continue

        mmdb_path = f"{ASN_MMDB_PREFIX}-{index}.mmdb"

        if not download_file(asn_mmdb_url, mmdb_path):
            raise RuntimeError(
                f"第 {index} 個 ASN MMDB 下載失敗"
            )

        try:
            extract_asn_mmdb(mmdb_path, output_data)
        finally:
            if os.path.exists(mmdb_path):
                os.remove(mmdb_path)

    print("\n[ Output ] 正在輸出 data 檔案")
    write_data_files(output_data)

    print("\n所有 Country、ASN 同自訂 IP 規則處理完畢！")


if __name__ == "__main__":
    main()
