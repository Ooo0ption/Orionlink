// E1: the in-process local-overhead measurement behind paper §6 Table III, one
// function per table row.
package e1

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	broker "secure-sso/Broker"
	idp "secure-sso/IdP"
	rp "secure-sso/RP"
	comm "secure-sso/internal/common"
	orionconf "secure-sso/internal/config"
	"secure-sso/internal/protocol"
	"secure-sso/lib"

	"github.com/cloudflare/circl/ecc/bls12381"
)

// setupServers is Table III "Initialization / Key generation": it brings the IdP
// and RP up in-process, generating the PS credential key pairs and the AAKA
// identity key.
func setupServers() (*idp.IdPServer, *rp.RPServer, *broker.BrokerServer, error) {
	idpServer := idp.NewIdPLocalServer()
	idpServer.CredKey = &comm.ServerCredKey{
		PSKey1: lib.PSKeyGen(1),
		PSKey2: lib.PSKeyGen(2),
	}
	sk, pk := lib.GenerateEmpKey()
	idpServer.IdentityKey = lib.DHKey{SK: sk, PK: pk}
	if err := idpServer.InitTokenAndRefreshForTest(orionconf.Get().Issuer()); err != nil {
		return nil, nil, nil, err
	}
	rpServer := rp.NewRPLocalServer()
	rpServer.ServerCredPk = comm.ServerCredPk{
		Vk1: idpServer.CredKey.PSKey1.PublicKey,
		Vk2: idpServer.CredKey.PSKey2.PublicKey,
	}
	rpServer.IdPAAKEPk = idpServer.IdentityKey.PK
	rpServer.Domain = []byte(orionconf.Get().RP.Browser + "/callback")

	brokerServer := broker.NewBrokerLocalServer()

	return idpServer, rpServer, brokerServer, nil
}

// performRegistration is Table III "Registration / RP registers to IdP": the blind
// issuance of the RP's DomainCred and SecretCred.
func performRegistration(idpServer *idp.IdPServer, rpServer *rp.RPServer) error {
	var idpRequest protocol.RPRegisterToIdPRequest
	d, err := rpServer.PrepareIdPRegistrationForTest(&idpRequest)
	if err != nil {
		return err
	}

	idpResponse, err := idpServer.ProcessRegistrationForTest(&idpRequest)
	if err != nil {
		return err
	}

	if err := rpServer.ProcessCredentialForTest(idpResponse, d); err != nil {
		return err
	}

	return nil
}

// generateACIDAndAUID is Table III "SSO / Pseudonym generation": it randomizes the
// DomainCred into a per-session acid, derives the blinded auid, and unblinds it to
// uid_rp.
func generateACIDAndAUID(rpServer *rp.RPServer) (*lib.PSSignMsg, *bls12381.Scalar, *bls12381.Scalar, string, string, error) {

	rSig1, k, tRand, err := lib.RandomizeSig(rpServer.DomainCred.Sigma)
	if err != nil {
		return nil, nil, nil, "", "", err
	}

	var domainScalar bls12381.Scalar
	domainScalar.SetBytes(rpServer.Domain)
	if !lib.VerifyRandomizedSig(rSig1, tRand, []*bls12381.Scalar{&domainScalar}, rpServer.ServerCredPk.Vk1) {
		return nil, nil, nil, "", "", err
	}

	uid := lib.NewRandomID()
	uidScalar := lib.HashStringToScalar(uid)
	auid := idp.GenerateAuid(rSig1.Sigma1, uidScalar)
	auidStr := comm.G1ToString(auid)
	uidRp, err := broker.GetUnblindAuid(auidStr, k)
	if err != nil {
		return nil, nil, nil, "", "", err
	}

	return rSig1, k, tRand, auidStr, uidRp, nil
}

// performAAKE is Table III "SSO / AnonyAKE execution": the RP proves knowledge of
// its credentials and both sides derive the X3DH session key K_S.
func performAAKE(idpServer *idp.IdPServer, rpServer *rp.RPServer, rSig1 *lib.PSSignMsg, tRand *bls12381.Scalar) ([]byte, []byte, error) {
	rSig1Bytes, err := rSig1.ToJSON()
	if err != nil {
		return nil, nil, err
	}
	pokReq := &protocol.AAKEGenPoKRequest{
		State: "test-state-123",
		RSig1: rSig1Bytes,
		T:     comm.ScalarToBytes(tRand),
	}

	pokResp, clientSk, clientPk, err := rpServer.GeneratePoKForTest(pokReq)
	if err != nil {
		return nil, nil, err
	}

	empResp, err := idpServer.GetIdPEmpKeyForTest()
	if err != nil {
		return nil, nil, err
	}

	serverEmpPk, err := comm.BytesToG1(empResp.PK)
	if err != nil {
		return nil, nil, err
	}

	KsRP, clientEmpPk, msgEnc, err := rpServer.NewSessionForTest(clientSk, clientPk, idpServer.IdentityKey.PK, serverEmpPk)
	if err != nil {
		return nil, nil, err
	}

	pokResp.E2EE = protocol.E2EE{
		ClientPK:    comm.G1ToBytes(clientPk),
		ClientEmpPK: comm.G1ToBytes(clientEmpPk),
		IdPEmpKeyId: empResp.KID,
		Msg:         msgEnc,
	}

	tokenReq := &protocol.AAKETokenRequest{
		Sign1: pokResp.Sign1,
		Sign2: pokResp.Sign2,
		C:     protocol.CGroup{C1: pokResp.C.C1, C2: pokResp.C.C2, C3: pokResp.C.C3},
		R:     protocol.RGroup{R1: pokResp.R.R1, R2: pokResp.R.R2, R3: pokResp.R.R3},
		Z:     protocol.ZGroup{ZD: pokResp.Z.ZD, ZQsk: pokResp.Z.ZQsk, Z1: pokResp.Z.Z1, Z2: pokResp.Z.Z2, Z3: pokResp.Z.Z3},
		E2EE:  pokResp.E2EE,
	}

	if ok, err := idpServer.VerifyPoKForTest(tokenReq); !ok || err != nil {
		return nil, nil, err
	}

	KsIdP, err := idpServer.NewSessionForTest(pokResp.E2EE)
	if err != nil {
		return nil, nil, err
	}

	return KsRP, KsIdP, nil
}

// performOPRF is Table III "Extension / Authorization revoke": the Ristretto255
// PIN-OPRF round trip that derives K_m for authorization management.
func performOPRF(idpServer *idp.IdPServer, rpServer *rp.RPServer) error {
	PIN := "123456"
	g := idpServer.GetOPRFGroup()
	P := g.HashToElement([]byte(PIN), nil)

	r := g.RandomScalar(rand.Reader)

	B := g.NewElement()
	B.Mul(P, r)

	B_bytes, err := B.MarshalBinary()
	if err != nil {
		return err
	}

	Z_bytes, err := idpServer.OPRFServerEvaluateForTest(B_bytes)
	if err != nil {
		return err
	}
	Z := g.NewElement()
	if err := Z.UnmarshalBinary(Z_bytes); err != nil {
		return err
	}

	rInv := g.NewScalar()
	rInv.Inv(r)

	beta := g.NewElement()
	beta.Mul(Z, rInv)

	_, err = beta.MarshalBinary()
	if err != nil {
		return err
	}

	return nil
}

// performRefreshLocal is Table III "Extension / Token refresh": one full
// RP to broker to IdP refresh, including the double-ratchet step.
func performRefreshLocal(idpServer *idp.IdPServer, brokerServer *broker.BrokerServer, rpServer *rp.RPServer) error {
	tid := "test-tid"
	uidRp := "test-uid-rp"

	refreshRPReq := &protocol.RefreshTokenFromRPRequest{
		TID:   tid,
		UIDRP: uidRp,
	}

	brokerReq, err := brokerServer.RefreshWithIdPLocalForTest(refreshRPReq)
	if err != nil {
		return fmt.Errorf("refresh: broker build idp refresh request failed: %w", err)
	}
	if brokerReq == nil {
		return errors.New("refresh: broker request is nil")
	}

	brokerResp, err := idpServer.RefreshFromBrokerForTest(brokerReq)
	if err != nil {
		return fmt.Errorf("refresh: idp handle refresh failed: %w", err)
	}
	if brokerResp == nil {
		return errors.New("refresh: idp response is nil")
	}

	accessToken, err := rpServer.DecryptRefreshResponseForTest(brokerResp)
	if err != nil {
		return fmt.Errorf("refresh: rp decrypt failed: %w", err)
	}
	if accessToken == "" {
		return errors.New("empty access token")
	}
	return nil
}

// progressInterval is how often a slow section reports its progress.
const progressInterval = 10 * time.Second

// benchLogf writes the harness's own output, bypassing the standard logger that
// WholeFlowLocal silences for the duration of a run.
func benchLogf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// timeSection runs body the given number of times and reports the mean that goes
// into Table III, emitting a progress line while a slow section is still running.
func timeSection(label string, iterations int, body func() error) error {
	benchLogf("========== %s ==========", label)

	start := time.Now()
	lastReport := start
	for i := 0; i < iterations; i++ {
		if err := body(); err != nil {
			return err
		}
		done := i + 1
		if done < iterations && time.Since(lastReport) >= progressInterval {
			elapsed := time.Since(start)
			eta := time.Duration(float64(elapsed) / float64(done) * float64(iterations-done))
			benchLogf("    %d/%d (%d%%)  elapsed %s, eta %s",
				done, iterations, done*100/iterations,
				elapsed.Truncate(time.Second), eta.Truncate(time.Second))
			lastReport = time.Now()
		}
	}
	mean := time.Since(start) / time.Duration(iterations)
	benchLogf("Average time: %v (%d iterations)", mean, iterations)
	recordSection(label, iterations, mean)
	return nil
}

// sectionRow is one Table III row as it lands in the E1 report.
type sectionRow struct {
	Stage      string  `json:"stage"`
	Operation  string  `json:"operation"`
	Iterations int     `json:"iterations"`
	MeanMs     float64 `json:"mean_ms"`
}

var e1Rows []sectionRow

// recordSection turns a section label into a report row. Labels look like
// "Part 3: Pseudonym generation [Table III: SSO]"; the Complete Flow section
// carries "[not a Table III row]" and is skipped, matching what run-e1.sh prints.
func recordSection(label string, iterations int, mean time.Duration) {
	open := strings.LastIndex(label, "[")
	if open < 0 || !strings.HasPrefix(label[open:], "[Table III: ") {
		return
	}
	stage := strings.TrimSuffix(strings.TrimPrefix(label[open:], "[Table III: "), "]")
	operation := strings.TrimSpace(label[:open])
	if colon := strings.Index(operation, ": "); colon >= 0 {
		operation = operation[colon+2:]
	}
	e1Rows = append(e1Rows, sectionRow{
		Stage:      stage,
		Operation:  operation,
		Iterations: iterations,
		MeanMs:     float64(mean.Nanoseconds()) / 1e6,
	})
}

// writeE1Report writes benchmark/results/e1-wholeflow-<profile>.json — the same six rows
// run-e1.sh prints, so the table can be re-read without re-running the test.
func writeE1Report(iterations int) (string, error) {
	profile := os.Getenv("ORION_PROFILE")
	if profile == "" {
		profile = "demo"
	}
	outDir := os.Getenv("ORION_PERF_OUT")
	if outDir == "" {
		outDir = filepath.Join("benchmark", "results")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}

	total := 0.0
	for _, r := range e1Rows {
		total += r.MeanMs
	}
	report := struct {
		Experiment  string       `json:"experiment"`
		PaperTable  string       `json:"paper_table"`
		Profile     string       `json:"profile"`
		Iterations  int          `json:"iterations"`
		GeneratedAt string       `json:"generated_at"`
		Rows        []sectionRow `json:"rows"`
		TotalMs     float64      `json:"total_ms"`
	}{
		Experiment:  "e1",
		PaperTable:  "Table III — local computation overhead",
		Profile:     profile,
		Iterations:  iterations,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Rows:        e1Rows,
		TotalMs:     total,
	}

	blob, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	outFile := filepath.Join(outDir, fmt.Sprintf("e1-wholeflow-%s.json", profile))
	if err := os.WriteFile(outFile, blob, 0o644); err != nil {
		return "", err
	}
	return outFile, nil
}

// WholeFlowLocal runs the six-part local-overhead measurement of paper §6
// Table III plus a Complete Flow section, and returns the first error it hits.
func WholeFlowLocal(iterations int) error {
	if iterations < 1 {
		return fmt.Errorf("iterations must be >= 1, got %d", iterations)
	}
	e1Rows = nil

	prevLogWriter := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prevLogWriter)

	if err := timeSection("Part 1: Key generation [Table III: Initialization]", iterations, func() error {
		_, _, _, err := setupServers()
		return err
	}); err != nil {
		return fmt.Errorf("Part 1 (init): %w", err)
	}

	idpServer, rpServer, brokerServer, err := setupServers()
	if err != nil {
		return fmt.Errorf("Part 2 setup: %w", err)
	}
	if err := timeSection("Part 2: RP registers to IdP [Table III: Registration]", iterations, func() error {
		return performRegistration(idpServer, rpServer)
	}); err != nil {
		return fmt.Errorf("Part 2 (registration): %w", err)
	}

	if err := performRegistration(idpServer, rpServer); err != nil {
		return fmt.Errorf("Part 3 setup registration: %w", err)
	}
	if err := timeSection("Part 3: Pseudonym generation [Table III: SSO]", iterations, func() error {
		_, _, _, _, _, err := generateACIDAndAUID(rpServer)
		return err
	}); err != nil {
		return fmt.Errorf("Part 3 (ACID/AUID): %w", err)
	}

	rSig1, _, tRand, _, _, err := generateACIDAndAUID(rpServer)
	if err != nil {
		return fmt.Errorf("Part 4 setup ACID/AUID: %w", err)
	}
	if err := timeSection("Part 4: AnonyAKE execution [Table III: SSO]", iterations, func() error {
		_, _, err := performAAKE(idpServer, rpServer, rSig1, tRand)
		return err
	}); err != nil {
		return fmt.Errorf("Part 4 (AAKE): %w", err)
	}

	if err := timeSection("Part 5: Authorization revoke [Table III: Extension]", iterations, func() error {
		return performOPRF(idpServer, rpServer)
	}); err != nil {
		return fmt.Errorf("Part 5 (OPRF): %w", err)
	}

	tid := "test-tid"
	uidRp := "test-uid-rp"
	rsk := make([]*bls12381.Scalar, 0, iterations+2)
	rpk := make([]*bls12381.G1, 0, iterations+2)
	for j := 0; j < iterations+2; j++ {
		sk, pk := lib.GenerateEmpKey()
		rsk = append(rsk, sk)
		rpk = append(rpk, pk)
	}
	if err := rpServer.SetRefreshKeyPairsForTest(rsk, rpk); err != nil {
		return fmt.Errorf("Part 6 refresh setup (rp keypairs): %w", err)
	}
	rpDHPks := make([][]byte, 0, len(rpk))
	for _, pk := range rpk {
		rpDHPks = append(rpDHPks, comm.G1ToBytes(pk))
	}
	refreshToken1, err := idpServer.GenerateRefreshTokenForTest(uidRp, "offline_access", "test-aud")
	if err != nil {
		return fmt.Errorf("Part 6 refresh setup (token): %w", err)
	}
	if err := brokerServer.InitRPIdentityForTest(tid, rpDHPks, uidRp, refreshToken1); err != nil {
		return fmt.Errorf("Part 6 refresh setup (broker state): %w", err)
	}
	if err := timeSection("Part 6: Token refresh [Table III: Extension]", iterations, func() error {
		return performRefreshLocal(idpServer, brokerServer, rpServer)
	}); err != nil {
		return fmt.Errorf("Part 6 (refresh): %w", err)
	}

	if err := timeSection("Complete Flow [not a Table III row]", iterations, func() error {
		idpS, rpS, brokerS, err := setupServers()
		if err != nil {
			return fmt.Errorf("Complete Flow setup: %w", err)
		}
		if err := performRegistration(idpS, rpS); err != nil {
			return fmt.Errorf("Complete Flow registration: %w", err)
		}
		rSig, _, tR, _, _, err := generateACIDAndAUID(rpS)
		if err != nil {
			return fmt.Errorf("Complete Flow ACID/AUID: %w", err)
		}
		if _, _, err := performAAKE(idpS, rpS, rSig, tR); err != nil {
			return fmt.Errorf("Complete Flow AAKE: %w", err)
		}
		if err := performOPRF(idpS, rpS); err != nil {
			return fmt.Errorf("Complete Flow OPRF: %w", err)
		}

		rsk2 := make([]*bls12381.Scalar, 0, 2)
		rpk2 := make([]*bls12381.G1, 0, 2)
		for j := 0; j < 2; j++ {
			sk, pk := lib.GenerateEmpKey()
			rsk2 = append(rsk2, sk)
			rpk2 = append(rpk2, pk)
		}
		if err := rpS.SetRefreshKeyPairsForTest(rsk2, rpk2); err != nil {
			return fmt.Errorf("Complete Flow refresh setup (rp keypairs): %w", err)
		}
		rpDHPks2 := make([][]byte, 0, len(rpk2))
		for _, pk := range rpk2 {
			rpDHPks2 = append(rpDHPks2, comm.G1ToBytes(pk))
		}
		refreshToken2, err := idpS.GenerateRefreshTokenForTest(uidRp, "offline_access", "test-aud")
		if err != nil {
			return fmt.Errorf("Complete Flow refresh setup (token): %w", err)
		}
		if err := brokerS.InitRPIdentityForTest(tid, rpDHPks2, uidRp, refreshToken2); err != nil {
			return fmt.Errorf("Complete Flow refresh setup (broker state): %w", err)
		}
		if err := performRefreshLocal(idpS, brokerS, rpS); err != nil {
			return fmt.Errorf("Complete Flow refresh: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	outFile, err := writeE1Report(iterations)
	if err != nil {
		return fmt.Errorf("write E1 report: %w", err)
	}
	benchLogf("wrote %s", outFile)
	return nil
}
