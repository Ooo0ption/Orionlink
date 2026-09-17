// Package tokenrefresh is a local token-refresh microbenchmark. It stands the
// IdP and broker up on host loopback ports and decrypts at the RP in process, so
// it deliberately does not represent container RTT and is not used by E2.
//
// It reports four segments:
//
//	broker_http_ms   POST /ssso/refresh to the broker, exactly as the RP issues
//	                 it: the broker handler, the broker to IdP hop, the IdP's
//	                 ratchet and mint, and the JSON decode of the response.
//	rp_decrypt_ms    the RP's own share, decrypting the relayed blob.
//	refresh_only_ms  the sum of those two: everything on the request path.
//	rp_keygen_ms     one RP DH key pair. The ratchet consumes one per refresh,
//	                 but the RP pre-generates a batch at startup, so this is an
//	                 amortised cost rather than request latency.
//
// The browser to RP request is not included: that endpoint sits behind a login
// session, which cannot be established without a full browser flow.
package tokenrefresh

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	broker "secure-sso/Broker"
	idp "secure-sso/IdP"
	rp "secure-sso/RP"
	comm "secure-sso/internal/common"
	orionconf "secure-sso/internal/config"
	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gofiber/fiber/v2"
)

const (
	benchTID   = "refresh-bench-tid"
	benchUIDRP = "refresh-bench-uid-rp"

	warmupRounds = 5

	keypairSlack = 8
)

func iterations() int {
	if v := os.Getenv("ORION_REFRESH_ITERATIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 100
}

func profile() string {
	if v := os.Getenv("ORION_PROFILE"); v != "" {
		return v
	}
	return "demo"
}

func outDir() string {
	if v := os.Getenv("ORION_PERF_OUT"); v != "" {
		return v
	}
	return filepath.Join("..", "..", "results")
}

// summary mirrors the shape and percentile convention of the browser harness's
// report, so results from the two can be read side by side.
type summary struct {
	N        int     `json:"n"`
	MeanMs   float64 `json:"mean_ms"`
	StddevMs float64 `json:"stddev_ms"`
	MinMs    float64 `json:"min_ms"`
	P50Ms    float64 `json:"p50_ms"`
	P95Ms    float64 `json:"p95_ms"`
	MaxMs    float64 `json:"max_ms"`
}

func summarize(samples []float64) summary {
	sorted := append([]float64(nil), samples...)
	sort.Float64s(sorted)

	var sum float64
	for _, v := range samples {
		sum += v
	}
	mean := sum / float64(len(samples))

	var acc float64
	for _, v := range samples {
		acc += (v - mean) * (v - mean)
	}
	variance := acc / math.Max(1, float64(len(samples)-1))

	at := func(q float64) float64 {
		i := int(q * float64(len(sorted)))
		if i > len(sorted)-1 {
			i = len(sorted) - 1
		}
		return sorted[i]
	}
	return summary{
		N:        len(samples),
		MeanMs:   mean,
		StddevMs: math.Sqrt(variance),
		MinMs:    sorted[0],
		P50Ms:    at(0.5),
		P95Ms:    at(0.95),
		MaxMs:    sorted[len(sorted)-1],
	}
}

type report struct {
	Table4Rows  []string           `json:"table4_rows"`
	Profile     string             `json:"profile"`
	Iterations  int                `json:"iterations"`
	GeneratedAt string             `json:"generated_at"`
	Transport   string             `json:"transport"`
	Stages      map[string]summary `json:"stages"`
}

// serve hands an already-bound loopback listener to a Fiber app and returns its
// base URL, so the port is reserved before any request is attempted.
func serve(t *testing.T, register func(*fiber.App)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback listener: %v", err)
	}
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	register(app)

	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	return "http://" + ln.Addr().String()
}

// postRefresh mirrors the RP's own POST helper, so timing it yields the RP's view
// of the hop.
func postRefresh(client *http.Client, url string, req *protocol.RefreshTokenFromRPRequest, out *protocol.RefreshTokenToRPResponse) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("broker returned status %d, body: %s", resp.StatusCode, raw)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode broker response: %w", err)
	}
	return nil
}

func TestRefreshOverHTTP(t *testing.T) {
	n := iterations()
	total := n + warmupRounds + keypairSlack

	idpServer := idp.NewIdPLocalServer()
	idpServer.CredKey = &comm.ServerCredKey{
		PSKey1: lib.PSKeyGen(1),
		PSKey2: lib.PSKeyGen(2),
	}
	sk, pk := lib.GenerateEmpKey()
	idpServer.IdentityKey = lib.DHKey{SK: sk, PK: pk}
	if err := idpServer.InitTokenAndRefreshForTest(orionconf.Get().Issuer()); err != nil {
		t.Fatalf("idp token/refresh init: %v", err)
	}
	idpURL := serve(t, idpServer.UseSecureSSO)

	brokerServer := broker.NewBrokerClientServer(broker.NewTokenHelper(), &broker.SecureSSOConfig{
		IdPRefreshURL: idpURL + "/ssso/refresh",
	})
	brokerURL := serve(t, brokerServer.UseSecureSSO)

	rpServer := rp.NewRPLocalServer()

	rsk := make([]*bls12381.Scalar, 0, total)
	rpk := make([]*bls12381.G1, 0, total)
	keygenMs := make([]float64, 0, total)
	for i := 0; i < total; i++ {
		tk := time.Now()
		s, p := lib.GenerateEmpKey()
		keygenMs = append(keygenMs, float64(time.Since(tk).Microseconds())/1000)
		rsk = append(rsk, s)
		rpk = append(rpk, p)
	}
	if err := rpServer.SetRefreshKeyPairsForTest(rsk, rpk); err != nil {
		t.Fatalf("rp refresh keypairs: %v", err)
	}
	rpDHPks := make([][]byte, 0, len(rpk))
	for _, p := range rpk {
		rpDHPks = append(rpDHPks, comm.G1ToBytes(p))
	}

	refreshToken, err := idpServer.GenerateRefreshTokenForTest(benchUIDRP, "offline_access", "test-aud")
	if err != nil {
		t.Fatalf("idp mint refresh token: %v", err)
	}
	if err := brokerServer.InitRPIdentityForTest(benchTID, rpDHPks, benchUIDRP, refreshToken); err != nil {
		t.Fatalf("broker seed rp identity: %v", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	refreshURL := brokerURL + "/ssso/refresh"
	req := &protocol.RefreshTokenFromRPRequest{TID: benchTID, UIDRP: benchUIDRP}

	one := func() (brokerMs, rpMs float64, err error) {
		var resp protocol.RefreshTokenToRPResponse

		t0 := time.Now()
		if err := postRefresh(client, refreshURL, req, &resp); err != nil {
			return 0, 0, err
		}
		brokerMs = float64(time.Since(t0).Microseconds()) / 1000

		t1 := time.Now()
		token, err := rpServer.DecryptRefreshResponseForTest(&resp)
		if err != nil {
			return 0, 0, fmt.Errorf("rp decrypt: %w", err)
		}
		rpMs = float64(time.Since(t1).Microseconds()) / 1000
		if token == "" {
			return 0, 0, fmt.Errorf("rp decrypted an empty access token")
		}
		return brokerMs, rpMs, nil
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, _, err := one(); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("servers did not become ready: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	prevOut := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prevOut)

	for i := 0; i < warmupRounds; i++ {
		if _, _, err := one(); err != nil {
			t.Fatalf("warmup round %d: %v", i, err)
		}
	}

	keygenSamples := keygenMs[warmupRounds : warmupRounds+n]

	brokerSamples := make([]float64, 0, n)
	rpSamples := make([]float64, 0, n)
	refreshOnlySamples := make([]float64, 0, n)
	totalSamples := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		b, r, err := one()
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		brokerSamples = append(brokerSamples, b)
		rpSamples = append(rpSamples, r)
		refreshOnlySamples = append(refreshOnlySamples, b+r)
		totalSamples = append(totalSamples, b+r+keygenSamples[i])
	}
	log.SetOutput(prevOut)

	rep := report{
		Table4Rows:  []string{},
		Profile:     profile(),
		Iterations:  n,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Transport:   "in-process IdP+Broker on loopback HTTP; RP decrypt in-process; no browser",
		Stages: map[string]summary{
			"broker_http_ms":  summarize(brokerSamples),
			"rp_decrypt_ms":   summarize(rpSamples),
			"rp_keygen_ms":    summarize(keygenSamples),
			"refresh_only_ms": summarize(refreshOnlySamples),
			"total_server_ms": summarize(totalSamples),
		},
	}

	if err := os.MkdirAll(outDir(), 0o755); err != nil {
		t.Fatalf("create output dir: %v", err)
	}
	outFile := filepath.Join(outDir(), fmt.Sprintf("micro-refresh_loopback-%s.json", rep.Profile))
	blob, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(outFile, blob, 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	t.Logf("\nrefresh_loopback_micro  profile=%s  iterations=%d", rep.Profile, rep.Iterations)
	for _, key := range []string{
		"broker_http_ms", "rp_decrypt_ms", "refresh_only_ms",
		"rp_keygen_ms", "total_server_ms",
	} {
		s := rep.Stages[key]
		t.Logf("  %-18s mean %9.3f ms  p50 %9.3f  p95 %9.3f  sd %.3f",
			key, s.MeanMs, s.P50Ms, s.P95Ms, s.StddevMs)
	}
	t.Logf("\nwrote %s", outFile)
}
