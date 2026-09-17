// Broker side of the token-refresh ratchet: per-RP state and the relay to the IdP.
package broker

import (
	"errors"
	"sync"

	comm "secure-sso/internal/common"
	"secure-sso/internal/protocol"

	"github.com/gofiber/fiber/v2"
)

// brokerRefreshState is one RP's ratchet position: the next sequence number,
// the RP's DH prekey list, and the last header seen from the IdP.
type brokerRefreshState struct {
	seq        uint32
	rpDHPks    [][]byte
	lastIdPHdr []byte
}

// RefreshTokenHelper holds the Broker's per-TID ratchet state and drives the
// Broker/IdP refresh relay.
type RefreshTokenHelper struct {
	mu sync.Mutex
	st map[string]*brokerRefreshState
}

// NewRefreshTokenHelper returns a helper with no per-RP ratchet state yet.
func NewRefreshTokenHelper() *RefreshTokenHelper {
	return &RefreshTokenHelper{
		st: make(map[string]*brokerRefreshState),
	}
}

// InitForRP resets the ratchet for one RP to sequence 0 with the given prekeys.
func (h *RefreshTokenHelper) InitForRP(tid string, rpDHPks [][]byte) {
	if tid == "" || len(rpDHPks) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.st[tid] = &brokerRefreshState{
		seq:     0,
		rpDHPks: rpDHPks,
	}
}

// ensureState returns the ratchet state for tid, creating it from rpDHPks when
// the broker has not seen a refresh for this RP yet.
func (h *RefreshTokenHelper) ensureState(tid string, rpDHPks [][]byte) (*brokerRefreshState, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.st[tid]; ok && s != nil && len(s.rpDHPks) > 0 {
		return s, nil
	}
	if len(rpDHPks) == 0 {
		return nil, errors.New("missing rp_dh_pks for tid")
	}
	s := &brokerRefreshState{seq: 0, rpDHPks: rpDHPks}
	h.st[tid] = s
	return s, nil
}

// RefreshWithIdP sends (hdr, seq, refresh_token) to the IdP and returns the
// (hdr, seq, c) response for relaying to the RP.
func (h *RefreshTokenHelper) RefreshWithIdP(
	srv *BrokerServer,
	c *fiber.Ctx,
	tid string,
	rpDHPks [][]byte,
	refreshToken string,
) (*protocol.RefreshTokenToRPResponse, error) {
	if srv == nil || c == nil {
		return nil, errors.New("nil context")
	}
	if tid == "" {
		return nil, errors.New("missing tid")
	}
	if refreshToken == "" {
		return nil, errors.New("missing refresh token")
	}
	state, err := h.ensureState(tid, rpDHPks)
	if err != nil {
		return nil, err
	}
	if int(state.seq) >= len(state.rpDHPks) {
		return nil, errors.New("rp dh key list exhausted")
	}

	req := &protocol.RefreshTokenFromBrokerRequest{
		Hdr:          state.rpDHPks[state.seq],
		Seq:          state.seq,
		RefreshToken: refreshToken,
	}
	resp := &protocol.RefreshTokenToRPResponse{}

	idpRefreshURL := srv.config.IdPRefreshURL
	if err := srv.sendPostRequest(c, idpRefreshURL, req, comm.StatusOK, resp); err != nil {
		return nil, err
	}

	h.mu.Lock()
	state.lastIdPHdr = resp.Hdr
	state.seq++
	h.mu.Unlock()

	return resp, nil
}
