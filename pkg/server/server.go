package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	common_keylime "github.com/keylime/spire-keylime-plugin/pkg/common"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// This compile-time assertion ensures the plugin conforms properly to the
	// pluginsdk.NeedsLogger interface.
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type Config struct {
	KeylimeVerifierHost  string `hcl:"keylime_verifier_host"`
	KeylimeVerifierPort  string `hcl:"keylime_verifier_port"`
	KeylimeTlsCACertFile string `hcl:"keylime_tls_ca_cert_file"`
	KeylimeTlsCertFile   string `hcl:"keylime_tls_cert_file"`
	KeylimeTlsKeyFile    string `hcl:"keylime_tls_key_file"`
	trustDomain          spiffeid.TrustDomain
}

type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	mtx  sync.RWMutex
	conf *Config
	log  hclog.Logger
}

type KeylimeVerifierStatusResponse struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Results struct {
		OperationalState int `json:"operational_state"`
	} `json:"results"`
}

type KeylimeVerifierValidateResponse struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Results struct {
		Valid int `json:"valid"`
	} `json:"results"`
}

// pemWrapCert accepts either PEM or bare base64 DER and returns PEM.
//
// The keylime REGISTRAR stores mtls_cert as bare base64 DER; the VERIFIER stores and requires PEM.
// Idempotent, so a registrar that ever starts returning PEM keeps working.
func pemWrapCert(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "-----BEGIN CERTIFICATE-----") {
		return s
	}
	s = strings.Join(strings.Fields(s), "")
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	for i := 0; i < len(s); i += 64 {
		end := i + 64
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		b.WriteString("\n")
	}
	b.WriteString("-----END CERTIFICATE-----\n")
	return b.String()
}

type KeylimeAgentAddRequest struct {
	TpmPolicy               string `json:"tpm_policy"`
	MetaData                string `json:"metadata"`
	MbRefstate              string `json:"mb_refstate"`
	MbPolicy                string `json:"mb_policy"`
	ImaSignVerificationKeys string `json:"ima_sign_verification_keys"`
	RuntimePolicy           string `json:"runtime_policy"`
	RuntimePolicyName       string `json:"runtime_policy_name"`
	MbPolicyName            string `json:"mb_policy_name"`
	RevocationKey           string `json:"revocation_key"`
	AcceptTpmHashAlgs       string `json:"accept_tpm_hash_algs"`
	AcceptTpmEncryptionAlgs string `json:"accept_tpm_encryption_algs"`
	AcceptTpmSigningAlgs    string `json:"accept_tpm_signing_algs"`
	AkTpm                   string `json:"ak_tpm"`
	MtlsCert                string `json:"mtls_cert"`
	SupportedVersion        string `json:"supported_version"`
	CloudAgentIP            string `json:"cloudagent_ip"`
	CloudAgentPort          string `json:"cloudagent_port"`
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	conf, _ := p.getConfig()
	// Receive attestation request
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	// Unmarshall received attestation data
	keylimeAgentData := new(common_keylime.AttestationRequest)
	err = json.Unmarshal(payload, keylimeAgentData)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall attestation data: %v", err)
	}
	agentID := string(keylimeAgentData.AgentID)
	hashAlg := string(keylimeAgentData.HashAlg)

	// Create an HTTP client that can speak TLS with the Keylime verifier
	keylimeCACert, err := ioutil.ReadFile(conf.KeylimeTlsCACertFile)
	if err != nil {
		log.Fatal(err)
	}
	keylimeCACertPool := x509.NewCertPool()
	keylimeCACertPool.AppendCertsFromPEM(keylimeCACert)

	keylimeCert, err := tls.LoadX509KeyPair(conf.KeylimeTlsCertFile, conf.KeylimeTlsKeyFile)
	if err != nil {
		log.Fatal(err)
	}
	// TODO - configure timeouts
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      keylimeCACertPool,
				Certificates: []tls.Certificate{keylimeCert},
			},
		},
	}

	keylimeVerifierUrl := fmt.Sprintf("https://%s:%s/%s", conf.KeylimeVerifierHost, conf.KeylimeVerifierPort, common_keylime.KeylimeAPIVersion)

	// Check the attested status of this node in Keylime
	keylimeStatusUrl := fmt.Sprintf("%s/agents/%s", keylimeVerifierUrl, agentID)
	p.log.Debug("Making request to Keylime verifier", "url", keylimeStatusUrl)
	statusReq, err := http.NewRequest(http.MethodGet, keylimeStatusUrl, nil)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to create HTTP request to Keylime verifier for %s: %s", keylimeStatusUrl, err)
	}
	statusRes, err := httpClient.Do(statusReq)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to contact Keylime verifier at %s: %s", keylimeStatusUrl, err)
	}
	p.log.Debug("Request results", "url", keylimeStatusUrl, "response", statusRes.StatusCode)

	// If agent doesn't exist in verifier (404), add it
	if statusRes.StatusCode == http.StatusNotFound {
		p.log.Info("Agent not found in verifier, adding it", "agent_uuid", agentID)

		// Get AK from registrar
		registrarUrl := fmt.Sprintf("https://registrar.keylime.funlab.casa:8891/%s/agents/%s", common_keylime.KeylimeAPIVersion, agentID)
		p.log.Debug("Fetching AK from registrar", "url", registrarUrl)
		regReq, err := http.NewRequest(http.MethodGet, registrarUrl, nil)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to create registrar request: %v", err)
		}
		regRes, err := httpClient.Do(regReq)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to contact registrar: %v", err)
		}
		defer regRes.Body.Close()

		var regResults struct {
			Code    int `json:"code"`
			Results struct {
				AikTpm   string `json:"aik_tpm"`
				IP       string `json:"ip"`
				Port     int    `json:"port"`
				MtlsCert string `json:"mtls_cert"`
			} `json:"results"`
		}
		err = json.NewDecoder(regRes.Body).Decode(&regResults)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to decode registrar response: %v", err)
		}
		akTpm := regResults.Results.AikTpm

		// Agent mTLS certificate, from the REGISTRAR rather than a hardcoded file.
		//
		// This previously read /etc/spire/keylime/auth-agent-cert.pem and sent it for EVERY agent it
		// registered. Measured 2026-09-02: that file is AUTH's certificate --
		// CN=agent.keylime.auth.funlab.casa, SANs covering only 10.10.2.70 and 127.0.0.1 -- and it
		// EXPIRED on Feb 21 2026. All seven agents in the verifier nonetheless carried it, because
		// keylime never validates the stored certificate's expiry; it only has to PARSE. The fleet's
		// verifier-to-agent mTLS therefore ran entirely on an expired certificate issued to a single
		// host, and nothing anywhere reported it.
		//
		// The registrar holds the real per-agent certificate and this code already fetches the AK
		// from it. The registrar stores BARE BASE64 DER while the verifier stores and requires PEM:
		// sending it unwrapped yields "X509: NO_CERTIFICATE_OR_CRL_FOUND", and an unparseable value
		// is UNRECOVERABLE -- the verifier cannot build an ssl_context, so it never polls the agent
		// and can never complete a DELETE either, leaving the record deadlocked in TERMINATED.
		mtlsCertContent := pemWrapCert(regResults.Results.MtlsCert)
		if mtlsCertContent == "" {
			// Fall back to the shared file rather than registering with no certificate, but be loud:
			// this path means the agent inherits another host's identity.
			certPath := "/etc/spire/keylime/auth-agent-cert.pem"
			certBytes, ferr := ioutil.ReadFile(certPath)
			if ferr != nil {
				p.log.Warn("registrar returned no mtls_cert and the fallback file is unreadable; registering without a certificate",
					"agent_uuid", agentID, "path", certPath, "error", ferr)
				certBytes = []byte{}
			} else {
				p.log.Warn("registrar returned no mtls_cert; FALLING BACK to the shared file, which is NOT this agent's own certificate",
					"agent_uuid", agentID, "path", certPath)
			}
			mtlsCertContent = string(certBytes)
		} else {
			p.log.Info("Using this agent's own mTLS certificate from the registrar",
				"agent_uuid", agentID, "cert_bytes", len(mtlsCertContent))
		}
		p.log.Debug("Retrieved AK from registrar", "ak_length", len(akTpm))
		// Create agent add request with minimal policy
		// IMA Runtime Policy - Phase 2: Exclude-based policy (no allowlist)
		imaPolicyJSON := `{
  "meta": {
    "version": 5,
    "generator": 0
  },
  "release": 0,
  "digests": {},
  "excludes": [
    "/var/",
    "/tmp/",
    "/home/",
    "/proc/",
    "/sys/",
    "/dev/shm/",
    "/run/",
    "/dev/",
    "/sys/firmware/"
  ],
  "keyrings": {},
  "ima": {
    "ignored_keyrings": [],
    "log_hash_alg": "sha256",
    "dm_policy": null
  },
  "ima-buf": {},
  "verification-keys": ""
}`
		runtimePolicy := base64.StdEncoding.EncodeToString([]byte(imaPolicyJSON))

		addRequest := KeylimeAgentAddRequest{
			TpmPolicy:               `{"mask": "0x90"}`,
			MetaData:                "{}",
			MbRefstate:              "",
			MbPolicy:                "",
			MbPolicyName:            "",
			ImaSignVerificationKeys: "[]",
			RevocationKey:           "",
			AcceptTpmHashAlgs:       "[\"sha256\", \"sha384\", \"sha512\"]",
			AcceptTpmEncryptionAlgs: "[\"rsa\", \"rsa2048\", \"ecc\"]",
			AcceptTpmSigningAlgs:    "[\"rsassa\", \"rsapss\", \"ecdsa\", \"ecdaa\", \"ecschnorr\"]",
			AkTpm:                   akTpm,
			RuntimePolicy:           runtimePolicy,
			RuntimePolicyName:       "",
			SupportedVersion:        "2.5",
			MtlsCert:                mtlsCertContent,
			CloudAgentIP:            regResults.Results.IP,
			CloudAgentPort:          fmt.Sprintf("%d", regResults.Results.Port),
		}
		addBody, err := json.Marshal(addRequest)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to marshal agent add request: %v", err)
		}
		p.log.Debug("Agent add request body", "json", string(addBody))

		// POST to add agent to verifier
		addUrl := keylimeStatusUrl
		p.log.Debug("Adding agent to verifier", "url", addUrl)
		addReq, err := http.NewRequest(http.MethodPost, addUrl, strings.NewReader(string(addBody)))
		if err != nil {
			return status.Errorf(codes.Internal, "unable to create add agent request: %v", err)
		}
		addReq.Header.Set("Content-Type", "application/json")

		addRes, err := httpClient.Do(addReq)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to add agent to verifier: %v", err)
		}
		p.log.Debug("Add agent response", "status", addRes.StatusCode)

		if addRes.StatusCode != http.StatusOK && addRes.StatusCode != http.StatusCreated {
			bodyBytes, _ := ioutil.ReadAll(addRes.Body)
			return status.Errorf(codes.Internal, "failed to add agent to verifier, status %d: %s", addRes.StatusCode, string(bodyBytes))
		}

		p.log.Info("Successfully added agent to verifier", "agent_uuid", agentID)

		// Re-check status after adding
		statusReq, _ = http.NewRequest(http.MethodGet, keylimeStatusUrl, nil)
		statusRes, err = httpClient.Do(statusReq)
		if err != nil {
			return status.Errorf(codes.Internal, "unable to check agent status after adding: %v", err)
		}
	}

	var statusResults KeylimeVerifierStatusResponse
	err = json.NewDecoder(statusRes.Body).Decode(&statusResults)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to read HTTP response body from %s: %s", keylimeStatusUrl, err)
	}
	keylimeOpState := statusResults.Results.OperationalState
	p.log.Debug("Keylime Verifier Status Results", "operational_state", keylimeOpState)

	// Wait for agent to reach valid state with retry logic
	// Valid states: 1 (Registered), 3 (Get Quote - verified), 4 (Provide V - verified)
	maxRetries := 15
	retryDelay := 2 * time.Second

	for i := 0; i < maxRetries && (keylimeOpState != 1 && keylimeOpState != 3 && keylimeOpState != 4); i++ {
		p.log.Debug("Agent not yet in valid state, waiting", "agent_uuid", agentID, "state", keylimeOpState, "retry", i+1)
		time.Sleep(retryDelay)

		// Re-check status
		statusReq, _ = http.NewRequest(http.MethodGet, keylimeStatusUrl, nil)
		statusRes, err = httpClient.Do(statusReq)
		if err == nil {
			json.NewDecoder(statusRes.Body).Decode(&statusResults)
			keylimeOpState = statusResults.Results.OperationalState
			p.log.Debug("Updated agent state", "operational_state", keylimeOpState)
		}
	}

	// Final check after retries
	if keylimeOpState != 1 && keylimeOpState != 3 && keylimeOpState != 4 {
		return status.Errorf(codes.Internal, "Keylime agent is not in a valid state after %d retries. Current state: %d (expected: 1=Registered, 3=Get Quote, or 4=Provide V)", maxRetries, keylimeOpState)
	}
	p.log.Info("Agent in valid state", "agent_uuid", agentID, "state", keylimeOpState)

	// Create a nonce for use in a quote
	keylimeNonce, err := common_keylime.NewNonce()
	if err != nil {
		return status.Errorf(codes.Internal, "unable to generate nonce for challenge: %v", err)
	}

	// Marshal challenges
	challenge, err := json.Marshal(common_keylime.ChallengeRequest{
		Nonce: []byte(keylimeNonce),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenges data: %v", err)
	}

	// Send challenges to the agent
	err = stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challenge,
		},
	})
	if err != nil {
		return status.Errorf(status.Code(err), "unable to send challenges: %v", err)
	}

	// Receive challenges response
	responseReq, err := stream.Recv()
	if err != nil {
		return status.Errorf(status.Code(err), "unable to receive challenges response: %v", err)
	}

	// Unmarshal challenges response
	challengeResponse := &common_keylime.ChallengeResponse{}
	if err = json.Unmarshal(responseReq.GetChallengeResponse(), challengeResponse); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall challenges response: %v", err)
	}
	TPMQuote := string(challengeResponse.TPMQuote)
	p.log.Debug("Received TPM Quote from agent", "tpm_quote", TPMQuote)

	// send TPM quote to Keylime Verifier to validate
	keylimeValidateUrl := fmt.Sprintf("%s/verify/identity", keylimeVerifierUrl)
	p.log.Debug("Making request to Keylime verifier", "url", keylimeValidateUrl)
	validateReq, err := http.NewRequest(http.MethodGet, keylimeValidateUrl, nil)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to create HTTP request to Keylime verifier for %s: %s", keylimeValidateUrl, err)
	}
	q := validateReq.URL.Query()
	q.Add("agent_uuid", agentID)
	q.Add("hash_alg", hashAlg)
	q.Add("nonce", keylimeNonce)
	q.Add("quote", TPMQuote)
	validateReq.URL.RawQuery = q.Encode()

	validateRes, err := httpClient.Do(validateReq)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to contact Keylime verifier at %s: %s", keylimeValidateUrl, err)
	}
	p.log.Debug("Request results", "url", keylimeValidateUrl, "response", validateRes.StatusCode)
	var validateResults KeylimeVerifierValidateResponse
	err = json.NewDecoder(validateRes.Body).Decode(&validateResults)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to read HTTP response body from %s: %s", keylimeValidateUrl, err)
	}
	keylimeIdentityValid := validateResults.Results.Valid
	p.log.Debug("Keylime Verifier Validate Results", "valid", keylimeIdentityValid)

	if keylimeIdentityValid != 1 {
		return status.Errorf(codes.Internal, "Keylime agent did not pass identity check")
	} else {
		p.log.Info("Keylime Attestation Successful")
	}

	// Create SPIFFE ID and selectors
	spiffeID, err := common_keylime.AgentID(p.conf.trustDomain, fmt.Sprintf("/%s/%s", common_keylime.PluginName, keylimeAgentData.AgentID))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to create agent ID: %v", err)
	}

	//return status.Errorf(codes.Internal, "FAILING FOR TESTING")

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest: true,
				SpiffeId:    spiffeID.String(),
			},
		},
	})
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	p.log.Warn("In Configure")
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	// get the trustdomain from the core config
	trustDomain, err := parseCoreConfig(req.CoreConfiguration)
	if err != nil {
		return nil, err
	}
	config.trustDomain = trustDomain

	// Validate configuration before setting/replacing existing configuration
	if err := validatePluginConfig(config); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid configuration: %v", err)
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func parseCoreConfig(c *configv1.CoreConfiguration) (spiffeid.TrustDomain, error) {
	if c == nil {
		return spiffeid.TrustDomain{}, status.Error(codes.InvalidArgument, "core configuration is missing")
	}

	if c.TrustDomain == "" {
		return spiffeid.TrustDomain{}, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	trustDomain, err := spiffeid.TrustDomainFromString(c.TrustDomain)
	if err != nil {
		return spiffeid.TrustDomain{}, status.Errorf(codes.InvalidArgument, "trust_domain is invalid: %v", err)
	}

	return trustDomain, nil
}

// SetLogger sets this plugin's logger
func (p *Plugin) SetLogger(logger hclog.Logger) {
	fmt.Println("HI!")
	p.log = logger
}

// setConfig replaces the configuration atomically under a write lock.
func (p *Plugin) setConfig(config *Config) {
	p.mtx.Lock()
	p.conf = config
	p.mtx.Unlock()
}

// getConfig gets the configuration under a read lock.
func (p *Plugin) getConfig() (*Config, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	if p.conf == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.conf, nil
}

func validatePluginConfig(c *Config) error {
	// set defaults if empty
	if c.KeylimeVerifierHost == "" {
		c.KeylimeVerifierHost = "127.0.0.1"
	}

	if c.KeylimeVerifierPort == "" {
		c.KeylimeVerifierPort = "8881"
	}

	if c.KeylimeTlsCACertFile == "" {
		c.KeylimeTlsCACertFile = "/var/lib/keylime/cv_ca/cacert.crt"
	}

	if c.KeylimeTlsCertFile == "" {
		c.KeylimeTlsCertFile = "/var/lib/keylime/cv_ca/server-cert.crt"
	}

	if c.KeylimeTlsKeyFile == "" {
		c.KeylimeTlsKeyFile = "/var/lib/keylime/cv_ca/server-private.pem"
	}

	// check if port is an integer between 0 and 65535
	portNum, err := strconv.Atoi(c.KeylimeVerifierPort)
	if err != nil {
		return errors.New("keylime_verifier_port is not a number")
	}
	if portNum < 0 {
		return errors.New("keylime_verifier_port is too small to be a port")
	}
	if portNum > 65535 {
		return errors.New("keylime_verifier_port is too large to be a port")
	}

	// validate that the key and cert files exists
	if _, err := os.Stat(c.KeylimeTlsCertFile); err != nil {
		return errors.New("keylime_tls_cert_file does not exist")
	}
	if _, err := os.Stat(c.KeylimeTlsKeyFile); err != nil {
		return errors.New("keylime_tls_key_file does not exist")
	}

	return nil
}

func newNonce(size int) ([]byte, error) {
	nonce, err := common_keylime.GetRandomBytes(size)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func main() {
	plugin := new(Plugin)
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
