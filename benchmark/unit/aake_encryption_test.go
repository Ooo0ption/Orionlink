// Unit test for the encryption of user attributes in IdP-issued tokens.
package unit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	idp "secure-sso/IdP"
	"secure-sso/lib"
)

// TestGenerateTokensEncryptsClaims asserts that every user-attribute value the
// IdP puts into a token is AES-GCM ciphertext under K_S, while the envelope claims
// stay plaintext so the broker can route and re-sign.
func TestGenerateTokensEncryptsClaims(t *testing.T) {
	s := idp.NewIdPLocalServer()

	const (
		uid      = "test-uid-902988"
		username = "Alice"
		email    = "Alice@example.com"
		scope    = "openid profile email"
		acid     = "test-acid-opaque-string"
	)
	ks := make([]byte, 32)
	for i := range ks {
		ks[i] = byte(i)
	}

	idTok, accessTok, refreshTok, err := s.GenerateTokensForTest(uid, username, email, scope, acid, ks)
	if err != nil {
		t.Fatalf("GenerateTokensForTest: %v", err)
	}

	idClaims := mustDecodeJWTPayload(t, idTok)
	accessClaims := mustDecodeJWTPayload(t, accessTok)
	refreshClaims := mustDecodeJWTPayload(t, refreshTok)

	encSub := strOf(idClaims["sub"])
	encName := strOf(idClaims["name"])
	encEmail := strOf(idClaims["email"])
	assertNotPlaintext(t, "id_token.sub", encSub, uid)
	assertNotPlaintext(t, "id_token.name", encName, username)
	assertNotPlaintext(t, "id_token.email", encEmail, email)
	if got := strOf(firstOf(idClaims["aud"])); got != acid {
		t.Errorf("id_token aud first = %q, want %q (envelope must stay plaintext)", got, acid)
	}

	assertNotPlaintext(t, "access_token.sub", strOf(accessClaims["sub"]), uid)
	assertNotPlaintext(t, "access_token.scope", strOf(accessClaims["scope"]), scope)

	if got := strOf(refreshClaims["sub"]); got != uid {
		t.Errorf("refresh_token.sub = %q, want plaintext %q (refresh ratchet handles encryption)", got, uid)
	}

	for name, ct := range map[string]string{"sub": encSub, "name": encName, "email": encEmail} {
		pt, err := lib.AESDecryptString(ks, ct)
		if err != nil {
			t.Fatalf("RP decrypt id_token.%s: %v", name, err)
		}
		want := map[string]string{"sub": uid, "name": username, "email": email}[name]
		if pt != want {
			t.Errorf("RP decrypt id_token.%s = %q, want %q", name, pt, want)
		}
	}
}

func assertNotPlaintext(t *testing.T, field, got, plaintext string) {
	t.Helper()
	if got == "" {
		t.Errorf("%s is empty (encryption may have silently failed)", field)
		return
	}
	if got == plaintext {
		t.Errorf("%s = %q is plaintext (must be K_S ciphertext)", field, got)
		return
	}
	if strings.Contains(got, plaintext) {
		t.Errorf("%s = %q still contains plaintext substring %q", field, got, plaintext)
	}
}

// mustDecodeJWTPayload returns a token's claims without verifying its signature,
// which is the view the broker has of them.
func mustDecodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT (parts=%d)", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("jwt b64 decode: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("jwt json: %v", err)
	}
	return m
}

func strOf(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// firstOf unwraps aud, which is encoded as either a string or a one-element array.
func firstOf(v any) any {
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		return arr[0]
	}
	return v
}
