import os
import json
import re
import urllib.request

# 建立 output 資料夾
os.makedirs("data", exist_ok=True)

# 載入標準 config.json
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

# 支援多個基底 MMDB
base_mmdb_urls = config.get("base_mmdb_urls", [])

# 向下兼容舊版 base_mmdb_url
legacy_base_mmdb_url = config.get("base_mmdb_url", "")
if legacy_base_mmdb_url and not base_mmdb_urls:
    base_mmdb_urls = [legacy_base_mmdb_url]

# 清除舊 MMDB，避免上次執行殘留
for filename in os.listdir("."):
    if re.fullmatch(r"base-\d+\.mmdb", filename):
        os.remove(filename)

for index, base_mmdb_url in enumerate(base_mmdb_urls, start=1):
    output_name = f"base-{index}.mmdb"

    print(
        f"[ Base MMDB {index}/{len(base_mmdb_urls)} ] "
        f"正在下載基底數據庫: {base_mmdb_url}"
    )

    req = urllib.request.Request(
        base_mmdb_url,
        headers={"User-Agent": "Mozilla/5.0"}
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            content = response.read()

        if not content:
            raise RuntimeError("下載內容為空")

        with open(output_name, "wb") as out_file:
            out_file.write(content)

        print(
            f"  └─ 下載成功：{output_name} "
            f"({len(content):,} bytes)"
        )

    except Exception as e:
        raise RuntimeError(
            f"下載 MMDB 失敗：{base_mmdb_url}，原因：{e}"
        ) from e

def fetch_content(source):
    if source.startswith("http://") or source.startswith("https://"):
        print(f"  └─ 正在下載遠端規則: {source}")
        req = urllib.request.Request(source, headers={'User-Agent': 'Mozilla/5.0'})
        try:
            with urllib.request.urlopen(req) as response:
                return response.read().decode('utf-8').splitlines()
        except Exception as e:
            print(f"  └─ 下載失敗 {source}: {e}")
            return []
    else:
        print(f"  └─ 正在讀取本地規則: {source}")
        if os.path.exists(source):
            with open(source, "r", encoding="utf-8") as f:
                return f.readlines()
        else:
            print(f"  └─ 警告：找不到本地檔案 {source}")
            return []

def clean_ip_cidr(ip_str):
    ip_str = ip_str.strip()
    if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$', ip_str):
        return f"{ip_str}/32"
    if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$', ip_str):
        return ip_str
    if ':' in ip_str:
        return ip_str if '/' in ip_str else f"{ip_str}/128"
    return None

def parse_line(line):
    line = line.strip()
    if not line or line.startswith('#') or line.startswith('//') or line.startswith('payload:'):
        return None
    if ' #' in line:
        line = line.split(' #', 1)[0]
    elif '//' in line and not line.startswith('http'):
        line = line.split('//', 1)[0]
        
    line = line.strip().lstrip('- ').replace("'", "").replace('"', '').strip()

    ip_part = line
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        rule_type = parts[0].upper()
        if rule_type.startswith("DOMAIN") or rule_type == "REGEXP":
            return None
        ip_part = parts[1]

    return clean_ip_cidr(ip_part)

categories = config.get("categories", config)

for tag, cat_data in categories.items():
    if tag.startswith("_"):
        continue

    print(f"\n[ Processing Category: {tag} ]")
    rules_set = set()
    exclude_set = set()

    exclude_list = cat_data.get("exclude_rules", []) if isinstance(cat_data, dict) else []
    for ex_line in exclude_list:
        parsed_ex = parse_line(ex_line)
        if parsed_ex:
            exclude_set.add(parsed_ex)

    sources = []
    inline_rules = []
    if isinstance(cat_data, dict):
        sources.extend(cat_data.get("urls", []))
        sources.extend(cat_data.get("local_files", []))
        inline_rules = cat_data.get("inline_rules", [])
    elif isinstance(cat_data, list):
        sources = cat_data

    for src_item in sources:
        src_url = src_item.get("url", "") if isinstance(src_item, dict) else src_item
        lines = fetch_content(src_url)
        for line in lines:
            parsed = parse_line(line)
            if parsed:
                rules_set.add(parsed)

    for inline_line in inline_rules:
        parsed = parse_line(inline_line)
        if parsed:
            rules_set.add(parsed)

    final_rules = rules_set - exclude_set

    out_path = f"data/{tag}"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(final_rules))) + "\n")
        
    print(f"  └─ Tag [{tag}] 完成: 最終輸出 {len(final_rules)} 條。")

print("\n所有 Category IP 處理完畢！")
