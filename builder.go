package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/maxminddb-golang"
)

type Config struct {
	BaseMMDBURL string              `json:"base_mmdb_url"`
	Categories  map[string]Category `json:"categories"`
}

type Category struct {
	URLs         []interface{} `json:"urls"`
	LocalFiles   []string      `json:"local_files"`
	InlineRules  []string      `json:"inline_rules"`
	ExcludeRules []string      `json:"exclude_rules"`
}

func main() {
	cfgData, err := os.ReadFile("config.json")
	if err != nil {
		fmt.Printf("Error reading config.json: %v\n", err)
		os.Exit(1)
	}

	var cfg Config
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		fmt.Printf("Error parsing config.json: %v\n", err)
		os.Exit(1)
	}

	// 1. 初始化 MMDB Writer
	var writer *mmdbwriter.Tree
	if cfg.BaseMMDBURL != "" {
		fmt.Printf("Downloading base MMDB from %s...\n", cfg.BaseMMDBURL)
		baseFile := "base.mmdb"
		if err := downloadFile(baseFile, cfg.BaseMMDBURL); err != nil {
			fmt.Printf("Failed to download base MMDB: %v\n", err)
			os.Exit(1)
		}

		reader, err := maxminddb.Open(baseFile)
		if err != nil {
			fmt.Printf("Failed to open base MMDB: %v\n", err)
			os.Exit(1)
		}
		defer reader.Close()

		// 設定允許處理重疊與 Aliased Network 的策略
		writer, err = mmdbwriter.Load(baseFile, mmdbwriter.Options{
			RecordSize:     24,
			InsertStrategy: mmdbwriter.ReplaceWithCloser,
		})
		if err != nil {
			fmt.Printf("Failed to load base MMDB into writer: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Successfully loaded base MMDB.")
	} else {
		writer, err = mmdbwriter.New(mmdbwriter.Options{
			DatabaseType: "GeoIP2-Country",
			RecordSize:   24,
		})
		if err != nil {
			fmt.Printf("Failed to create new MMDB writer: %v\n", err)
			os.Exit(1)
		}
	}

	// 2. 處理自訂 Categories
	os.MkdirAll("data", 0755)

	for tag, catData := range cfg.Categories {
		if strings.HasPrefix(tag, "_") {
			continue
		}
		fmt.Printf("\nProcessing Category: %s\n", tag)

		excludeMap := make(map[string]bool)
		for _, ex := range catData.ExcludeRules {
			if cidr := parseToCIDR(ex); cidr != "" {
				excludeMap[cidr] = true
			}
		}

		ruleMap := make(map[string]bool)

		// 處理 URLs
		for _, uItem := range catData.URLs {
			var urlStr string
			switch v := uItem.(type) {
			case string:
				urlStr = v
			case map[string]interface{}:
				if val, ok := v["url"].(string); ok {
					urlStr = val
				}
			}

			if urlStr != "" {
				lines := fetchLines(urlStr)
				for _, line := range lines {
					if cidr := parseToCIDR(line); cidr != "" {
						ruleMap[cidr] = true
					}
				}
			}
		}

		// 處理 local_files
		for _, lf := range catData.LocalFiles {
			lines := readLines(lf)
			for _, line := range lines {
				if cidr := parseToCIDR(line); cidr != "" {
					ruleMap[cidr] = true
				}
			}
		}

		// 處理 inline_rules
		for _, inline := range catData.InlineRules {
			if cidr := parseToCIDR(inline); cidr != "" {
				ruleMap[cidr] = true
			}
		}

		// 執行剔除與寫入
		var finalCIDRs []string
		for cidr := range ruleMap {
			if !excludeMap[cidr] {
				finalCIDRs = append(finalCIDRs, cidr)

				_, ipnet, err := net.ParseCIDR(cidr)
				if err == nil {
					// 注入 MMDB
					record := mmdbtype.Map{
						"country": mmdbtype.Map{
							"iso_code": mmdbtype.String(strings.ToUpper(tag)),
						},
					}
					// 捕捉單條網段插入異常，確保不會卡死
					if err := writer.Insert(ipnet, record); err != nil {
						fmt.Printf("Warning: Skipping insert for %s: %v\n", cidr, err)
					}
				}
			}
		}

		sort.Strings(finalCIDRs)
		os.WriteFile(filepath.Join("data", tag), []byte(strings.Join(finalCIDRs, "\n")+"\n"), 0644)
		fmt.Printf("  └─ Tag [%s] completed with %d CIDR entries.\n", tag, len(finalCIDRs))
	}

	// 3. 匯出合併後的 Country.mmdb
	outMMDB, err := os.Create("Country.mmdb")
	if err != nil {
		fmt.Printf("Failed to create Country.mmdb: %v\n", err)
		os.Exit(1)
	}
	defer outMMDB.Close()

	if _, err := writer.WriteTo(outMMDB); err != nil {
		fmt.Printf("Failed to write Country.mmdb: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nMerged Country.mmdb created successfully!")
}

func parseToCIDR(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "payload:") {
		return ""
	}

	if idx := strings.Index(line, " #"); idx != -1 {
		line = line[:idx]
	}

	line = strings.TrimPrefix(line, "- ")
	line = strings.ReplaceAll(line, "'", "")
	line = strings.ReplaceAll(line, "\"", "")
	line = strings.TrimSpace(line)

	parts := strings.Split(line, ",")
	ipPart := line
	if len(parts) >= 2 {
		ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
		if strings.HasPrefix(ruleType, "DOMAIN") || ruleType == "REGEXP" {
			return ""
		}
		ipPart = strings.TrimSpace(parts[1])
	}

	ip := net.ParseIP(ipPart)
	if ip != nil {
		if ip.To4() != nil {
			return ipPart + "/32"
		}
		return ipPart + "/128"
	}

	_, _, err := net.ParseCIDR(ipPart)
	if err == nil {
		return ipPart
	}

	return ""
}

func downloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func fetchLines(urlStr string) []string {
	resp, err := http.Get(urlStr)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var lines []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func readLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}
