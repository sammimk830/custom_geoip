import ipaddress
import json
import os
import re
import shutil
import urllib.request
from pathlib import Path
from typing import Any

import maxminddb


CONFIG_FILE = Path("config.json")
DATA_DIR = Path("data")

DOWNLOAD_TIMEOUT = 180
USER_AGENT = "Mozilla/5.0 custom_geoip_builder/1.0"


def download_file(url: str, output_path: Path) -> None:
    """下載檔案，失敗時直接終止 build。"""
    print(f"[Download] {url}")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=DOWNLOAD_TIMEOUT,
        ) as response:
            content = response.read()
    except Exception as exc:
        raise RuntimeError(
            f"下載失敗：{url}\n原因：{exc}"
        ) from exc

    if not content:
        raise RuntimeError(f"下載內容為空：{url}")

    output_path.write_bytes(content)

    print(
        f"  └─ 已儲存：{output_path} "
        f"({len(content):,} bytes)"
    )


def fetch_text(url: str) -> list[str]:
    """下載文字規則。"""
    print(f"  ├─ 下載規則：{url}")

    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=DOWNLOAD_TIMEOUT,
        ) as response:
            content = response.read().decode(
                "utf-8",
                errors="ignore",
            )
    except Exception as exc:
        raise RuntimeError(
            f"規則下載失敗：{url}\n原因：{exc}"
        ) from exc

    return content.splitlines()


def normalize_cidr(value: str) -> str | None:
    """將 IP 或 CIDR 正規化。"""
    value = value.strip()

    if not value:
        return None

    try:
        if "/" not in value:
            address = ipaddress.ip_address(value)
            prefix = 32 if address.version == 4 else 128
            return f"{address}/{prefix}"

        network = ipaddress.ip_network(
            value,
            strict=False,
        )
        return str(network)

    except ValueError:
        return None


def parse_rule_line(line: str) -> str | None:
    """
    支援：
    IP-CIDR,1.2.3.0/24
    IP-CIDR6,2001:db8::/32
    - IP-CIDR,1.2.3.0/24,no-resolve
    1.2.3.0/24
    """
    line = line.strip()

    if not line:
        return None

    if line.startswith(("#", "//")):
        return None

    if line.lower() in {
        "payload:",
        "rules:",
        "rule-providers:",
    }:
        return None

    line = line.lstrip("- ").strip()
    line = line.strip("'\"")

    # 移除行尾註解
    if " #" in line:
        line = line.split(" #", 1)[0].strip()

    parts = [part.strip() for part in line.split(",")]

    if len(parts) >= 2:
        rule_type = parts[0].upper()

        if rule_type in {
            "IP-CIDR",
            "IP-CIDR6",
            "SRC-IP-CIDR",
        }:
            return normalize_cidr(parts[1])

        # 忽略 Domain、GeoSite 等非 IP 規則
        return None

    return normalize_cidr(line)


def read_local_rules(file_path: str) -> list[str]:
    """讀取本機規則檔。"""
    path = Path(file_path)

    print(f"  ├─ 讀取本機規則：{path}")

    if not path.exists():
        raise FileNotFoundError(f"找不到本機規則檔：{path}")

    return path.read_text(
        encoding="utf-8",
        errors="ignore",
    ).splitlines()


def parse_rules(lines: list[str]) -> set[str]:
    result: set[str] = set()

    for line in lines:
        parsed = parse_rule_line(line)

        if parsed:
            result.add(parsed)

    return result


def get_asn(record: Any) -> int | None:
    """由 GeoLite2 ASN record 取出 ASN number。"""
    if not isinstance(record, dict):
        return None

    value = record.get("autonomous_system_number")

    if isinstance(value, int) and value > 0:
        return value

    if isinstance(value, str) and value.isdigit():
        number = int(value)

        if number > 0:
            return number

    return None


def extract_asn_mmdb(
    mmdb_path: Path,
    output_data: dict[str, set[str]],
) -> None:
    """
    將 ASN MMDB 拆成：
    data/as13335
    data/as15169
    data/as4515
    """
    print(f"[ASN MMDB] 處理：{mmdb_path}")

    valid_count = 0
    skipped_count = 0
    discovered_asns: set[int] = set()

    try:
        with maxminddb.open_database(str(mmdb_path)) as reader:
            for network, record in reader:
                asn = get_asn(record)

                if asn is None:
                    skipped_count += 1
                    continue

                tag = f"as{asn}"

                output_data.setdefault(tag, set()).add(
                    str(network)
                )

                discovered_asns.add(asn)
                valid_count += 1

    except Exception as exc:
        raise RuntimeError(
            f"無法讀取 ASN MMDB：{mmdb_path}\n原因：{exc}"
        ) from exc

    if valid_count == 0:
        raise RuntimeError(
            f"ASN MMDB 無法產生任何規則：{mmdb_path}"
        )

    print(f"  ├─ ASN 數量：{len(discovered_asns):,}")
    print(f"  ├─ 有效 CIDR：{valid_count:,}")
    print(f"  └─ 跳過記錄：{skipped_count:,}")


def write_rule_files(
    output_data: dict[str, set[str]],
) -> None:
    """輸出 v2fly text input 規則檔。"""
    print("[Output] 輸出自訂及 ASN 規則")

    for tag in sorted(output_data):
        rules = output_data[tag]

        if not rules:
            print(f"  ├─ {tag}：無規則，已跳過")
            continue

        # 防止分類名稱包含路徑或特殊符號
        safe_tag = re.sub(
            r"[^a-zA-Z0-9_-]",
            "_",
            tag,
        ).lower()

        output_path = DATA_DIR / safe_tag

        sorted_rules = sorted(
            rules,
            key=lambda item: (
                ipaddress.ip_network(item).version,
                int(ipaddress.ip_network(item).network_address),
                ipaddress.ip_network(item).prefixlen,
            ),
        )

        output_path.write_text(
            "\n".join(sorted_rules) + "\n",
            encoding="utf-8",
        )

        print(
            f"  ├─ {safe_tag}："
            f"{len(sorted_rules):,} 條"
        )


def load_url_list(
    config: dict[str, Any],
    plural_key: str,
    legacy_key: str | None = None,
) -> list[str]:
    """同時支援 array 同舊版單一 URL。"""
    value = config.get(plural_key, [])

    if isinstance(value, str):
        urls = [value]
    elif isinstance(value, list):
        urls = [
            str(item)
            for item in value
            if str(item).strip()
        ]
    else:
        raise TypeError(
            f"{plural_key} 必須係字串或者陣列"
        )

    if not urls and legacy_key:
        legacy_value = config.get(legacy_key, "")

        if isinstance(legacy_value, str):
            legacy_value = legacy_value.strip()

            if legacy_value:
                urls.append(legacy_value)

    return urls


def process_categories(
    config: dict[str, Any],
) -> dict[str, set[str]]:
    output_data: dict[str, set[str]] = {}

    categories = config.get("categories", {})

    if not isinstance(categories, dict):
        raise TypeError("categories 必須係 JSON object")

    for category_name, settings in categories.items():
        if category_name.startswith("_"):
            continue

        if not isinstance(settings, dict):
            raise TypeError(
                f"分類 {category_name} 設定必須係 object"
            )

        print(f"[Category] {category_name}")

        rules: set[str] = set()

        urls = settings.get("urls", [])
        local_files = settings.get("local_files", [])
        inline_rules = settings.get("inline_rules", [])
        exclude_rules = settings.get("exclude_rules", [])

        if not isinstance(urls, list):
            raise TypeError(
                f"{category_name}.urls 必須係陣列"
            )

        if not isinstance(local_files, list):
            raise TypeError(
                f"{category_name}.local_files 必須係陣列"
            )

        if not isinstance(inline_rules, list):
            raise TypeError(
                f"{category_name}.inline_rules 必須係陣列"
            )

        if not isinstance(exclude_rules, list):
            raise TypeError(
                f"{category_name}.exclude_rules 必須係陣列"
            )

        for url in urls:
            rules.update(
                parse_rules(fetch_text(str(url)))
            )

        for file_path in local_files:
            rules.update(
                parse_rules(
                    read_local_rules(str(file_path))
                )
            )

        rules.update(
            parse_rules(
                [str(rule) for rule in inline_rules]
            )
        )

        exclusions = parse_rules(
            [str(rule) for rule in exclude_rules]
        )

        if exclusions:
            before_count = len(rules)
            rules.difference_update(exclusions)

            print(
                f"  ├─ 排除："
                f"{before_count - len(rules):,} 條"
            )

        if not rules:
            print("  └─ 警告：沒有產生任何 CIDR")
            continue

        output_data[category_name] = rules

        print(f"  └─ 有效規則：{len(rules):,} 條")

    return output_data


def main() -> None:
    if not CONFIG_FILE.exists():
        raise FileNotFoundError("找不到 config.json")

    with CONFIG_FILE.open(
        "r",
        encoding="utf-8",
    ) as config_file:
        config = json.load(config_file)

    # 每次重新建立，避免舊 ASN / 自訂分類殘留
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 移除上一次可能殘留嘅 Country MMDB
    for old_mmdb in Path(".").glob("base-*.mmdb"):
        old_mmdb.unlink()

    output_data = process_categories(config)

    # Country MMDB：保留原檔，交俾 v2fly maxmindMMDB
    country_mmdb_urls = load_url_list(
        config,
        plural_key="base_mmdb_urls",
        legacy_key="base_mmdb_url",
    )

    print(
        f"[Country MMDB] 數量："
        f"{len(country_mmdb_urls)}"
    )

    for index, url in enumerate(
        country_mmdb_urls,
        start=1,
    ):
        output_path = Path(f"base-{index}.mmdb")
        download_file(url, output_path)

    # ASN MMDB：拆成 data/asXXXX
    asn_mmdb_urls = load_url_list(
        config,
        plural_key="asn_mmdb_urls",
    )

    print(f"[ASN MMDB] 數量：{len(asn_mmdb_urls)}")

    for index, url in enumerate(
        asn_mmdb_urls,
        start=1,
    ):
        temporary_path = Path(
            f"asn-{index}.mmdb"
        )

        download_file(url, temporary_path)

        try:
            extract_asn_mmdb(
                temporary_path,
                output_data,
            )
        finally:
            temporary_path.unlink(missing_ok=True)

    write_rule_files(output_data)

    generated_files = list(DATA_DIR.glob("*"))

    if not generated_files:
        raise RuntimeError(
            "data 目錄沒有產生任何規則檔"
        )

    print()
    print("所有規則處理完成。")
    print(f"Country MMDB：{len(country_mmdb_urls)} 個")
    print(f"ASN MMDB：{len(asn_mmdb_urls)} 個")
    print(f"Text tags：{len(generated_files)} 個")


if __name__ == "__main__":
    main()
