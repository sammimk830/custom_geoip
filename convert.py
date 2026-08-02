```python
import ipaddress
import json
import re
import shutil
import urllib.request
from pathlib import Path
from typing import Any

import maxminddb


CONFIG_FILE = Path("config.json")
DATA_DIR = Path("data")

DOWNLOAD_TIMEOUT = 180
USER_AGENT = "Mozilla/5.0 custom_geoip_builder/1.1"


def download_file(url: str, output_path: Path) -> None:
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
    value = value.strip()

    if not value:
        return None

    try:
        if "/" not in value:
            address = ipaddress.ip_address(value)
            prefix = 32 if address.version == 4 else 128
            return f"{address}/{prefix}"

        return str(
            ipaddress.ip_network(
                value,
                strict=False,
            )
        )
    except ValueError:
        return None


def parse_rule_line(line: str) -> str | None:
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

        return None

    return normalize_cidr(line)


def read_local_rules(file_path: str) -> list[str]:
    path = Path(file_path)

    print(f"  ├─ 讀取本機規則：{path}")

    if not path.exists():
        raise FileNotFoundError(
            f"找不到本機規則檔：{path}"
        )

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


def normalize_asn_groups(
    config: dict[str, Any],
) -> dict[str, set[int]]:
    raw_groups = config.get("asn_groups", {})

    if raw_groups is None:
        return {}

    if not isinstance(raw_groups, dict):
        raise TypeError(
            "asn_groups 必須係 JSON object"
        )

    normalized: dict[str, set[int]] = {}

    for group_name, values in raw_groups.items():
        if not isinstance(group_name, str):
            raise TypeError(
                "asn_groups 嘅 group 名稱必須係字串"
            )

        safe_name = re.sub(
            r"[^a-zA-Z0-9_-]",
            "_",
            group_name.strip(),
        ).lower()

        if not safe_name:
            raise ValueError(
                "asn_groups 包含空白 group 名稱"
            )

        if not isinstance(values, list):
            raise TypeError(
                f"asn_groups.{group_name} 必須係陣列"
            )

        asn_numbers: set[int] = set()

        for value in values:
            if isinstance(value, str):
                value = value.strip().upper()

                if value.startswith("AS"):
                    value = value[2:]

                if not value.isdigit():
                    raise ValueError(
                        f"{group_name} 包含無效 ASN：{value}"
                    )

                number = int(value)

            elif isinstance(value, int):
                number = value

            else:
                raise TypeError(
                    f"{group_name} 包含無效 ASN 類型："
                    f"{type(value).__name__}"
                )

            if number <= 0:
                raise ValueError(
                    f"{group_name} 包含無效 ASN：{number}"
                )

            asn_numbers.add(number)

        if not asn_numbers:
            print(
                f"[ASN Group] {safe_name} 無 ASN，已跳過"
            )
            continue

        normalized[safe_name] = asn_numbers

    return normalized


def extract_selected_asn_mmdb(
    mmdb_path: Path,
    asn_groups: dict[str, set[int]],
    output_data: dict[str, set[str]],
) -> None:
    print(f"[ASN MMDB] 處理：{mmdb_path}")

    if not asn_groups:
        print("  └─ 無設定 asn_groups，跳過 ASN 提取")
        return

    asn_to_groups: dict[int, set[str]] = {}

    for group_name, asn_numbers in asn_groups.items():
        for asn in asn_numbers:
            asn_to_groups.setdefault(
                asn,
                set(),
            ).add(group_name)

    wanted_asns = set(asn_to_groups)
    found_asns: set[int] = set()
    matched_cidrs = 0

    try:
        with maxminddb.open_database(
            str(mmdb_path)
        ) as reader:
            for network, record in reader:
                asn = get_asn(record)

                if asn is None or asn not in wanted_asns:
                    continue

                found_asns.add(asn)
                cidr = str(network)

                for group_name in asn_to_groups[asn]:
                    output_data.setdefault(
                        group_name,
                        set(),
                    ).add(cidr)

                matched_cidrs += 1

    except Exception as exc:
        raise RuntimeError(
            f"無法讀取 ASN MMDB：{mmdb_path}\n"
            f"原因：{exc}"
        ) from exc

    print(f"  ├─ 指定 ASN：{len(wanted_asns):,}")
    print(f"  ├─ 搵到 ASN：{len(found_asns):,}")
    print(f"  └─ 匹配 CIDR：{matched_cidrs:,}")

    missing_asns = sorted(wanted_asns - found_asns)

    if missing_asns:
        missing_text = ", ".join(
            f"AS{asn}" for asn in missing_asns
        )

        print(
            f"  警告：以下 ASN 喺 MMDB 搵唔到："
            f"{missing_text}"
        )

    for group_name in sorted(asn_groups):
        count = len(output_data.get(group_name, set()))

        print(
            f"  ├─ Group {group_name}："
            f"{count:,} 條 CIDR"
        )


def write_rule_files(
    output_data: dict[str, set[str]],
) -> None:
    print("[Output] 輸出規則")

    for tag in sorted(output_data):
        rules = output_data[tag]

        if not rules:
            print(f"  ├─ {tag}：無規則，已跳過")
            continue

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
                int(
                    ipaddress.ip_network(
                        item
                    ).network_address
                ),
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
    value = config.get(plural_key, [])

    if isinstance(value, str):
        urls = [value.strip()] if value.strip() else []

    elif isinstance(value, list):
        urls = [
            str(item).strip()
            for item in value
            if str(item).strip()
        ]

    else:
        raise TypeError(
            f"{plural_key} 必須係字串或者陣列"
        )

    if not urls and legacy_key:
        legacy_value = config.get(
            legacy_key,
            "",
        )

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
        raise TypeError(
            "categories 必須係 JSON object"
        )

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
        local_files = settings.get(
            "local_files",
            [],
        )
        inline_rules = settings.get(
            "inline_rules",
            [],
        )
        exclude_rules = settings.get(
            "exclude_rules",
            [],
        )

        for field_name, field_value in {
            "urls": urls,
            "local_files": local_files,
            "inline_rules": inline_rules,
            "exclude_rules": exclude_rules,
        }.items():
            if not isinstance(field_value, list):
                raise TypeError(
                    f"{category_name}.{field_name} "
                    "必須係陣列"
                )

        for url in urls:
            rules.update(
                parse_rules(
                    fetch_text(str(url))
                )
            )

        for file_path in local_files:
            rules.update(
                parse_rules(
                    read_local_rules(
                        str(file_path)
                    )
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

        print(
            f"  └─ 有效規則："
            f"{len(rules):,} 條"
        )

    return output_data


def main() -> None:
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(
            "找不到 config.json"
        )

    with CONFIG_FILE.open(
        "r",
        encoding="utf-8",
    ) as config_file:
        config = json.load(config_file)

    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    for old_mmdb in Path(".").glob(
        "base-*.mmdb"
    ):
        old_mmdb.unlink()

    output_data = process_categories(config)

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
        output_path = Path(
            f"base-{index}.mmdb"
        )

        download_file(
            url,
            output_path,
        )

    asn_groups = normalize_asn_groups(config)

    asn_mmdb_urls = load_url_list(
        config,
        plural_key="asn_mmdb_urls",
    )

    print(
        f"[ASN MMDB] 數量："
        f"{len(asn_mmdb_urls)}"
    )
    print(
        f"[ASN Groups] 數量："
        f"{len(asn_groups)}"
    )

    if asn_groups and not asn_mmdb_urls:
        raise RuntimeError(
            "已設定 asn_groups，"
            "但 asn_mmdb_urls 為空"
        )

    if asn_mmdb_urls and not asn_groups:
        print(
            "[ASN MMDB] 無設定 asn_groups，"
            "不會下載或輸出 ASN 規則"
        )

    if asn_groups:
        for index, url in enumerate(
            asn_mmdb_urls,
            start=1,
        ):
            temporary_path = Path(
                f"asn-{index}.mmdb"
            )

            download_file(
                url,
                temporary_path,
            )

            try:
                extract_selected_asn_mmdb(
                    temporary_path,
                    asn_groups,
                    output_data,
                )
            finally:
                temporary_path.unlink(
                    missing_ok=True
                )

    write_rule_files(output_data)

    generated_files = [
        path
        for path in DATA_DIR.glob("*")
        if path.is_file()
    ]

    if not generated_files:
        raise RuntimeError(
            "data 目錄沒有產生任何規則檔"
        )

    print()
    print("所有規則處理完成。")
    print(
        f"Country MMDB："
        f"{len(country_mmdb_urls)} 個"
    )
    print(
        f"ASN MMDB："
        f"{len(asn_mmdb_urls) if asn_groups else 0} 個"
    )
    print(
        f"ASN Groups："
        f"{len(asn_groups)} 個"
    )
    print(
        f"Text tags："
        f"{len(generated_files)} 個"
    )


if __name__ == "__main__":
    main()
```
