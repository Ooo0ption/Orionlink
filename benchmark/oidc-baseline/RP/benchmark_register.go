package rp

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// BenchmarkRegister 基准测试RP注册功能
// iterations: 循环次数，如果为0则使用默认值10
func BenchmarkRegister() error {
	iterations := 10 // 默认循环10次

	// RP服务器地址（假设在本地运行）
	rpURL := os.Getenv("RP_URL")
	if rpURL == "" {
		rpURL = "http://localhost:14932" // 默认地址
	}

	registerEndpoint := rpURL + "/oauth2/register"

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	log.Printf("[INFO/RP] Starting registration benchmark test with %d iterations", iterations)

	var totalDuration int64
	var successCount int
	var failCount int

	// 准备注册请求
	reqBody := ClientRegistrationRequest{
		ClientName:   "Benchmark Test Client",
		RedirectURIs: []string{"http://localhost:14932/oauth2/callback"},
		ClientType:   "rp",
	}

	for i := 1; i <= iterations; i++ {
		log.Printf("[INFO/RP] Running registration test iteration %d/%d", i, iterations)

		// 序列化请求体
		jsonData, err := json.Marshal(reqBody)
		if err != nil {
			log.Printf("[ERROR/RP] Failed to marshal request: %v", err)
			failCount++
			continue
		}

		// 创建请求
		req, err := http.NewRequest("POST", registerEndpoint, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Printf("[ERROR/RP] Failed to create request: %v", err)
			failCount++
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		// 记录开始时间
		startTime := time.Now()

		// 发送请求
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR/RP] Failed to send request: %v", err)
			failCount++
			continue
		}

		// 读取响应（即使出错也要读取body）
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// 记录结束时间
		endTime := time.Now()
		duration := endTime.Sub(startTime).Milliseconds()

		// 检查响应状态
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			totalDuration += duration
			successCount++
			log.Printf("[INFO/RP] Iteration %d: SUCCESS - Duration: %dms", i, duration)

			// 解析响应以获取 ClientID（可选）
			var regResp ClientRegistrationResponse
			if err := json.Unmarshal(body, &regResp); err == nil {
				log.Printf("[INFO/RP] Iteration %d: Registered client ID: %s", i, regResp.ClientID)
			}
		} else {
			failCount++
			log.Printf("[ERROR/RP] Iteration %d: FAILED - Status: %d, Duration: %dms, Response: %s", i, resp.StatusCode, duration, string(body))
		}

		// 在每次迭代之间稍作延迟，避免过快请求
		if i < iterations {
			time.Sleep(100 * time.Millisecond)
		}
	}

	// 输出统计结果
	log.Printf("\n=== Registration Benchmark Results ===")
	log.Printf("Total Iterations: %d", iterations)
	log.Printf("Success: %d", successCount)
	log.Printf("Failed: %d", failCount)
	if successCount > 0 {
		avgDuration := totalDuration / int64(successCount)
		log.Printf("Average Duration: %dms", avgDuration)
		log.Printf("Total Duration: %dms", totalDuration)
	}

	return nil
}
