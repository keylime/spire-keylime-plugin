package keylime

import (
	"fmt"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// AgentID builds the SPIFFE ID for an attested agent.
//
// Inlined from github.com/spiffe/spire/pkg/common/idutil so the plugin does not depend on the
// whole SPIRE server module for nine lines. That dependency pulled in SPIRE's entire tree and,
// from v1.16, forces Go >= 1.26.6 on anyone building this plugin.
//
// THIS FUNCTION DEFINES EVERY AGENT'S IDENTITY. Its output is the SPIFFE ID recorded in the
// registration entries -- e.g. spiffe://example.org/spire/agent/keylime/<uuid>. Any change in
// behaviour, including a differently-formatted error, silently re-identifies the whole fleet and
// invalidates every entry. It is therefore a byte-for-byte copy of upstream v1.8.7, not a
// reimplementation, and pkg/common/spiffeid_test.go asserts it against the real agent IDs.
func AgentID(td spiffeid.TrustDomain, suffix string) (spiffeid.ID, error) {
	if td.IsZero() {
		return spiffeid.ID{}, fmt.Errorf("cannot create agent ID with suffix %q for empty trust domain", suffix)
	}
	if err := spiffeid.ValidatePath(suffix); err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid agent path suffix %q: %w", suffix, err)
	}
	return spiffeid.FromPath(td, "/spire/agent"+suffix)
}
