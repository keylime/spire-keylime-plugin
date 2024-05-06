package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	common_keylime "github.com/keylime/spire-keylime-plugin/pkg/common"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/idutil"
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
				RootCAs:            keylimeCACertPool,
				Certificates:       []tls.Certificate{keylimeCert},
				InsecureSkipVerify: true, // TODO - remove after development
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
	var statusResults KeylimeVerifierStatusResponse
	err = json.NewDecoder(statusRes.Body).Decode(&statusResults)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to read HTTP response body from %s: %s", keylimeStatusUrl, err)
	}
	keylimeOpState := statusResults.Results.OperationalState
	p.log.Debug("Keylime Verifier Status Results", "operational_state", keylimeOpState)

	// TODO - make this more robust and less hard-coded
	if keylimeOpState != 3 && keylimeOpState != 4 {
		return status.Errorf(codes.Internal, "Keylime agent is not in a verified state. Current state: %d", keylimeOpState)
	}

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
	}

	// Create SPIFFE ID and selectors
	spiffeID, err := idutil.AgentID(p.conf.trustDomain, fmt.Sprintf("/%s/%s", common_keylime.PluginName, keylimeAgentData.AgentID))
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
