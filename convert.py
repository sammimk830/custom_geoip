import json
import re
import urllib.request
import yaml

def fetch_and_parse_clash(url):
    """從遠端 URL 下載並解析 Clash IP 規則 (IP-CIDR, IP-CIDR6)"""
    cidrs = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
            matches = re.findall(r'IP-CIDR6?,([^,\s]+)', content, re.IGNORECASE)
            cidrs.extend(matches)
    except Exception as e:
        print(f"[Warning] 下載或解析失敗 {url}: {e}")
    return cidrs

def main():
    with open('config.json', 'r', encoding='utf-8') as f:
        config = json.load(f)

    # 下載底層 MMDB (若 config.json 有設定)
    if config.get("base_mmdb_url"):
        print("正喺度下載底層 base.mmdb...")
        try:
            urllib.request.urlretrieve(config["base_mmdb_url"], "base.mmdb")
        except Exception as e:
            print(f"[Warning] 下載 base.mmdb 失敗: {e}")

    output_data = {}

    for cat_name, sources in config.get("categories", {}).items():
        cat_cidrs = set()

        # 1. 抓取遠端 URL 規則
        for url in sources.get("urls", []):
            print(f"[{cat_name}] 正在抓取 URL: {url}")
            fetched = fetch_and_parse_clash(url)
            cat_cidrs.update(fetched)

        # 2. 讀取本機檔案
        for file_path in sources.get("local_files", []):
            try:
                with open(file_path, 'r', encoding='utf-8') as lf:
                    for line in lf:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            cat_cidrs.add(line)
            except Exception as e:
                print(f"[Warning] 無法讀取本機檔案 {file_path}: {e}")

        # 3. 處理直寫 (Inline) 規則
        for inline in sources.get("inline_rules", []):
            cat_cidrs.add(inline.strip())

        # 4. 執行 Exclude 過濾 (關鍵新增步驟)
        exclude_set = set(inline.strip() for inline in sources.get("exclude_rules", []))
        if exclude_set:
            print(f"[{cat_name}] 正在剔除 {len(exclude_set)} 條指定規則...")
            cat_cidrs = cat_cidrs - exclude_set  # 從集合中直接扣除

        output_data[cat_name] = sorted(list(cat_cidrs))

    # 輸出成 geoip-miner 可讀取嘅 YAML 格式
    with open('generated_rules.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(output_data, f, default_flow_style=False)
    
    print("generated_rules.yaml 已成功生成！")

if __name__ == '__main__':
    main()
