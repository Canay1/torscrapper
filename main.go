package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"strconv"

	"github.com/chromedp/chromedp"
	"golang.org/x/net/proxy"
)

func main() {
	printBanner()

	fmt.Println("Oturum Başladı")

	var filePath string
	flag.StringVar(&filePath, "f", "", "Yaml dosyasının yolu")
	flag.Parse()

	if filePath == "" {
		log.Fatal("Kullanım: go run main.go -f targets.yaml")
	}

	fmt.Printf("Şuradan hedefler yükleniyor: %s\n", filePath)
	urls, err := readURLs(filePath)
	if err != nil {
		log.Fatalf("Dosya okuma hatası: %v", err)
	}

	for i := range urls {
		urls[i] = strings.TrimSpace(urls[i])
		if !strings.HasPrefix(strings.ToLower(urls[i]), "http") {
			urls[i] = "http://" + urls[i]
		}
	}

	fmt.Printf("%d adet hedef okundu\n\n", len(urls))

	fmt.Println("Uygun hedefler:")
	for i, u := range urls {
		fmt.Printf("  %d: %s\n", i+1, u)
	}
	fmt.Print("\n Hedef araligi secin (orn: 1,3-5) veya 'all': ")
	var input string
	fmt.Scanln(&input)

	selectedURLs := parseSelection(input, urls)
	if len(selectedURLs) == 0 {
		fmt.Println("Hedef secilmedi cikiliyor.")
		return
	}
	fmt.Printf("%d adet hedef için tarama baslatiliyor.\n\n", len(selectedURLs))

	fmt.Println("Tor baglanti kontrolu basladi (port: 9150)")

	proxyURL, _ := url.Parse("socks5://127.0.0.1:9150")
	dialer, _ := proxy.FromURL(proxyURL, proxy.Direct)

	transport := &http.Transport{Dial: dialer.Dial}
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second}

	if testTorConnection(client) {
		fmt.Println("Tor baglantisi:Basarili\n")
	} else {
		fmt.Println("Tor baglantisi:Basarisiz\n")
	}

	fmt.Println("Tarama raporu ve sonuç klasörü oluşturuluyor...")
	logFile, _ := os.Create("scan_report.log")
	defer logFile.Close()
	logger := log.New(logFile, "", log.LstdFlags)

	outputDir := "tarama_sonuclari"
	os.MkdirAll(outputDir, 0755)

	total := len(selectedURLs)
	for i, targetURL := range selectedURLs {
		fmt.Printf("Taraniyor %d/%d: %s \n", i+1, total, targetURL)
		logger.Printf("Taraniyor %s", targetURL)

		htmlBody, title := scrapeHTMLAndTitle(client, targetURL, logger)
		if htmlBody == nil {
			fmt.Printf("Basarisiz (olu link yada zaman asimi)\n\n")
			continue
		}

		fileBaseName := cleanFileName(title)
		if fileBaseName == "" {
			fileBaseName = targetURL
		}
		timestamp := time.Now().Format("20060102_150405")
		htmlFileName := fmt.Sprintf("%s_%s.html", fileBaseName, timestamp)
		pngFileName := fmt.Sprintf("%s_%s.png", fileBaseName, timestamp)

		htmlPath := filepath.Join(outputDir, htmlFileName)
		pngPath := filepath.Join(outputDir, pngFileName)

		if err := os.WriteFile(htmlPath, htmlBody, 0644); err != nil {
			fmt.Printf("Html kaydetme hatasi: %v\n", err)
			logger.Printf("Html kaydetme hatasi %s: %v", targetURL, err)
		} else {
			fmt.Printf("Html basari ile kaydedildi -> %s\n", htmlFileName)
			logger.Printf("Html basari ile kaydedildi %s -> %s", targetURL, htmlFileName)
		}

		fmt.Printf("Screenshot aliniyor...\n")
		if err := takeScreenshot(targetURL, pngPath); err != nil {
			fmt.Printf("Screenshot basarisiz: %v\n", err)
			logger.Printf("Screenshot basarisiz %s: %v", targetURL, err)
		} else {
			fmt.Printf("Screenshot alindi -> %s\n", pngFileName)
			logger.Printf("Screenshot alindi %s -> %s", targetURL, pngFileName)
		}

		fmt.Println()
		time.Sleep(4 * time.Second)
	}

	fmt.Println("Tarama tamamlandi!")
	fmt.Println("Dosyalar (HTML + PNG): tarama_sonuclari/")
	fmt.Println("Log: scan_report.log")
}

func printBanner() {
	banner := `
   _____ ___  ____     ____ _____ _ 
  |_   _/ _ \|  _ \   / ___|_   _(_)
    | || | | | |_) | | |     | | | |
    | || |_| |  _ <  | |___  | | | |
    |_| \___/|_| \_\  \____| |_| |_|
                                    
     Tor Cyber Threat Intelligence Tool
	`
	fmt.Println(banner)
}

func cleanFileName(name string) string {
	reg := regexp.MustCompile(`[^a-zA-Z0-9\s\-_]+`)
	name = reg.ReplaceAllString(name, "_")
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, " ", "_")
	if len(name) > 100 {
		name = name[:100]
	}
	return name
}

func testTorConnection(client *http.Client) bool {
	req, _ := http.NewRequest("GET", "https://check.torproject.org/api/ip", nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return strings.Contains(string(body), `"IsTor":true`)
}

func scrapeHTMLAndTitle(client *http.Client, targetURL string, logger *log.Logger) ([]byte, string) {
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Hata: %v\n", err)
		logger.Printf("Hata %s: %v", targetURL, err)
		return nil, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("Durum: %d\n", resp.StatusCode)
		logger.Printf("%s: Durum %d", targetURL, resp.StatusCode)
		return nil, ""
	}

	body, _ := ioutil.ReadAll(resp.Body)

	re := regexp.MustCompile(`(?is)<title>(.*?)</title>`)
	match := re.FindSubmatch(body)
	title := "NoTitle"
	if len(match) > 1 {
		title = strings.TrimSpace(string(match[1]))
	}

	return body, title
}

func takeScreenshot(targetURL, outputPath string) error {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ProxyServer("socks5://127.0.0.1:9150"),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("host-resolver-rules", "MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"),
		chromedp.WindowSize(1920, 1080),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(6*time.Second),
		chromedp.FullScreenshot(&buf, 95),
	)
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, buf, 0644)
}

func readURLs(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

func parseSelection(input string, urls []string) []string {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "all" {
		return urls
	}

	var selected []string
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])
				for i := start - 1; i < end && i < len(urls); i++ {
					if i >= 0 {
						selected = append(selected, urls[i])
					}
				}
			}
		} else {
			idx, _ := strconv.Atoi(part)
			if idx > 0 && idx <= len(urls) {
				selected = append(selected, urls[idx-1])
			}
		}
	}
	return selected
}