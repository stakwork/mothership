package macaroon

import "fmt"

// ErrorCode is a machine-readable tag for a verification failure.
// Adapters translate these to bifrost.Error codes (or HTTP status
// codes) at their boundary.
type ErrorCode string

const (
	ErrMacaroonMalformed          ErrorCode = "macaroon_malformed"
	ErrMacaroonUnsupportedVersion ErrorCode = "macaroon_unsupported_version"
	ErrInvalidRootSignature       ErrorCode = "invalid_root_signature"
	ErrInvalidBlockSignature      ErrorCode = "invalid_block_signature"
	ErrInvalidProof               ErrorCode = "invalid_proof"
	ErrMacaroonExpired            ErrorCode = "macaroon_expired"
	ErrAgentNotPermitted          ErrorCode = "agent_not_permitted"
)

// VerifyError is the error type returned by [Verify]. Adapters
// dispatch on Code to pick the right transport response.
type VerifyError struct {
	Code   ErrorCode
	Detail string
}

func (e *VerifyError) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Detail)
}

func newError(code ErrorCode, detail string) *VerifyError {
	return &VerifyError{Code: code, Detail: detail}
}
