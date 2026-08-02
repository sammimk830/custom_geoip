import os
import json
import re
import urllib.request

# 建立 output 資料夾
os.makedirs("data", exist_ok=True)

# 載入標準 config.json
with open("config.json", "r", encoding="utf-8") as f:
    config = json.load(f)

def fetch_content(source):
    """判斷是網址還是本地檔案，並讀取內容"""
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
    """清洗並轉換為標準的 CIDR 格式"""
    ip_str = ip_str.strip()
    
    # 如果只有單個 IPv4 位址，自動補上 /32
    if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$', ip_str):
        return f"{ip_str}/32"
    
    # IPv4 CIDR
    if re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$', ip_str):
        return ip_str

    # IPv6 CIDR 或 單個 IPv6
    if ':' in ip_str:
        if '/' in ip_str:
            return ip_str
        else:
            return f"{ip_str}/128"

    return None

def parse_line(line):
    """提取並過濾 IP / CIDR 規則"""
    line = line.strip()
    
    # 1. 忽略註解與 YAML 結構標頭
    if not line or line.startswith('#') or line.startswith('//') or line.startswith('payload:'):
        return None
    
    # 2. 切除行內註解
    if ' #' in line:
        line = line.split(' #', 1)[0]
    elif '//' in line and not line.startswith('http'):
        line = line.split('//', 1)[0]
        
    line = line.strip()
    if not line:
        return None

    # 3. 清理 YAML 格式 (減號、單雙引號)
    line = line.lstrip('- ').strip()
    line = line.replace("'", "").replace('"', '').strip()

    rule_type = ""
    ip_part = line

    # 4. 處理 Clash 格式 (例如 IP-CIDR,192.168.1.0/24 或 IP-CIDR6,fe80::/10)
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        rule_type = parts[0].upper()
        ip_part = parts[1]

        # 如果明確是 DOMAIN / DOMAIN-SUFFIX 等域名類型，直接拋棄
        if rule_type in ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'REGEXP']:
            return None

    # 5. 格式化為標準 CIDR
    return clean_ip_cidr(ip_part)

# 取得 categories 結構
categories = config.get("categories", config)

for tag, cat_data in categories.items():
    if tag.startswith("_"):
        continue

    print(f"\n[ Processing Category: {tag} ]")
    rules_set = set()
    exclude_set = set()

    # 1. 解析 exclude_rules
    exclude_list = cat_data.get("exclude_rules", []) if isinstance(cat_data, dict) else []
    for ex_line in exclude_list:
        parsed_ex = parse_line(ex_line)
        if parsed_ex:
            exclude_set.add(parsed_ex)

    # 2. 彙整來源
    sources = []
    inline_rules = []
    
    if isinstance(cat_data, dict):
        sources.extend(cat_data.get("urls", []))
        sources.extend(cat_data.get("local_files", []))
        inline_rules = cat_data.get("inline_rules", [])
    elif isinstance(cat_data, list):
        sources = cat_data

    # 3. 下載與讀取檔案類來源
    for src_item in sources:
        src_url = src_item.get("url", "") if isinstance(src_item, dict) else src_item
        lines = fetch_content(src_url)
        for line in lines:
            parsed = parse_line(line)
            if parsed:
                rules_set.add(parsed)

    # 4. 處理 inline_rules
    for inline_line in inline_rules:
        parsed = parse_line(inline_line)
        if parsed:
            rules_set.add(parsed)

    # 5. 執行剔除邏輯
    final_rules = rules_set - exclude_set

    out_path = f"data/{tag}"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(final_rules))) + "\n")
        
    print(f"  └─ Tag [{tag}] 完成: 原始 {len(rules_set)} 條，排除 {len(exclude_set)} 條，最終輸出 {len(final_rules)} 條。")

print("\n所有 Category IP 規則處理完畢！")
