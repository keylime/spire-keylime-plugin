package keylime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	common_keylime "github.com/keylime/spire-keylime-plugin/pkg/common"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
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
	KeylimeAgentHost      string `hcl:"keylime_agent_host"`
	KeylimeAgentPort      string `hcl:"keylime_agent_port"`
	KeylimeAgentUseTLS    bool   `hcl:"keylime_agent_use_tls"`
	KeylimeAgentCACert    string `hcl:"keylime_agent_ca_cert"`
	KeylimeAgentClientCert string `hcl:"keylime_agent_client_cert"`
	KeylimeAgentClientKey  string `hcl:"keylime_agent_client_key"`
}

type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer
	log hclog.Logger

	mtx  sync.RWMutex
	conf *Config
	httpClient *http.Client
}

type KeylimeAgentInfoResponse struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Results struct {
		AgentUUID string `json:"agent_uuid"`
		HashAlg   string `json:"tpm_hash_alg"`
	} `json:"results"`
}

type KeylimeAgentIdentityResponse struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Results struct {
		Quote string `json:"quote"`
	} `json:"results"`
}

func New() *Plugin {
	return &Plugin{
		conf: &Config{},
	}
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := new(Config)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}

	p.log.Debug("Loaded Config Vars", "KeylimeAgentPort", config.KeylimeAgentPort, "KeylimeAgentHost", config.KeylimeAgentHost, "KeylimeAgentUseTLS", config.KeylimeAgentUseTLS)

	if err := validatePluginConfig(config); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid configuration: %v", err)
	}

	// Create HTTP client with TLS configuration if enabled
	httpClient, err := createHTTPClient(config, p.log)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to create HTTP client: %v", err)
	}

	p.setConfig(config, httpClient)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// getConfig gets the configuration under a read lock.
func (p *Plugin) getConfig() (*Config, *http.Client, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	if p.conf == nil {
		return nil, nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.conf, p.httpClient, nil
}

// setConfig replaces the configuration atomically under a write lock.
func (p *Plugin) setConfig(config *Config, httpClient *http.Client) {
	p.mtx.Lock()
	p.conf = config
	p.httpClient = httpClient
	p.mtx.Unlock()
}

func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	conf, httpClient, _ := p.getConfig()
	if conf == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	// Determine protocol based on TLS configuration
	protocol := "http"
	if conf.KeylimeAgentUseTLS {
		protocol = "https"
	}

	// keylime agent URL
	keylimeAgentUrl := fmt.Sprintf("%s://%s:%s/%s", protocol, conf.KeylimeAgentHost, conf.KeylimeAgentPort, common_keylime.KeylimeAPIVersion)

	// get keylime node information from keylime agent
	keylimeInfoUrl := fmt.Sprintf("%s/agent/info", keylimeAgentUrl)
	p.log.Debug("Making request to keylime agent", "url", keylimeInfoUrl)
	infoReq, err := http.NewRequest(http.MethodGet, keylimeInfoUrl, nil)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to create HTTP request to Keylime agent for %s: %s", keylimeInfoUrl, err)
	}
	infoRes, err := httpClient.Do(infoReq)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to contact Keylime agent at %s: %s", keylimeInfoUrl, err)
	}
	p.log.Debug("Request results", "url", keylimeInfoUrl, "response", infoRes.StatusCode)
	var infoResults KeylimeAgentInfoResponse
	err = json.NewDecoder(infoRes.Body).Decode(&infoResults)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to read HTTP response body from %s: %s", keylimeInfoUrl, err)
	}
	agentUUID := infoResults.Results.AgentUUID
	hashAlg := infoResults.Results.HashAlg
	p.log.Debug("Keylime Agent Info Results", "agent_uuid", agentUUID, "hash_alg", hashAlg)

	// Marshal attestation data
	p.log.Debug("Marshalling attestation request")
	marshaledAttData, err := json.Marshal(common_keylime.AttestationRequest{
		AgentID: []byte(agentUUID),
		HashAlg: []byte(hashAlg),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal attestation data: %v", err)
	}

	// Send attestation request
	p.log.Debug("Sending attestation request")
	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: marshaledAttData,
		},
	})
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send attestation data: %s", st.Message())
	}

	// Receive challenge
	p.log.Debug("Receiving attestation challenge")
	marshalledChallenge, err := stream.Recv()
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to receive challenge: %s", st.Message())
	}
	challenge := &common_keylime.ChallengeRequest{}
	p.log.Debug("Unmarchalling attestation challenge")
	if err = json.Unmarshal(marshalledChallenge.Challenge, challenge); err != nil {
		return status.Errorf(codes.InvalidArgument, "unable to unmarshall challenge: %v", err)
	}
	nonce := string(challenge.Nonce)
	p.log.Debug("Received nonce for attestation challenge", "nonce", nonce)

	// Get an identity verification from the Keylime agent
	keylimeIdentityUrl := fmt.Sprintf("%s/quotes/identity", keylimeAgentUrl)
	p.log.Debug("Making request to keylime agent", "url", keylimeIdentityUrl)
	identityReq, err := http.NewRequest(http.MethodGet, keylimeIdentityUrl, nil)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to create HTTP request to Keylime agent for %s: %s", keylimeIdentityUrl, err)
	}
	q := identityReq.URL.Query()
	q.Add("nonce", string(nonce))
	identityReq.URL.RawQuery = q.Encode()

	identityRes, err := httpClient.Do(identityReq)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to contact Keylime agent at %s: %s", keylimeIdentityUrl, err)
	}
	p.log.Debug("Request results", "url", keylimeIdentityUrl, "response", identityRes.StatusCode)
	var identityResults KeylimeAgentIdentityResponse
	err = json.NewDecoder(identityRes.Body).Decode(&identityResults)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to read HTTP response body from %s: %s", keylimeIdentityUrl, err)
	}
	quote := identityResults.Results.Quote
	p.log.Debug("Keylime Agent Identity Results", "quote", quote)

	// Marshal challenges responses
	p.log.Debug("Mashalling challenge response")
	marshalledChallengeResp, err := json.Marshal(common_keylime.ChallengeResponse{
		TPMQuote: []byte(quote),
	})
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal challenge response: %v", err)
	}

	// Send challenge response back to the server
	p.log.Debug("Sending challenge response")
	err = stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: marshalledChallengeResp,
		},
	})
	if err != nil {
		st := status.Convert(err)
		return status.Errorf(st.Code(), "unable to send challenge response: %s", st.Message())
	}
	p.log.Info("Keylime Attestation response sent")

	return nil
}

func createHTTPClient(config *Config, log hclog.Logger) (*http.Client, error) {
	if !config.KeylimeAgentUseTLS {
		log.Debug("TLS disabled, using default HTTP client")
		return http.DefaultClient, nil
	}

	log.Debug("Configuring TLS for Keylime agent connection")

	// Create TLS configuration
	tlsConfig := &tls.Config{}

	// Load CA certificate if provided
	if config.KeylimeAgentCACert != "" {
		caCert, err := os.ReadFile(config.KeylimeAgentCACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %v", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
		log.Debug("Loaded CA certificate", "path", config.KeylimeAgentCACert)
	}

	// Load client certificate and key if provided
	if config.KeylimeAgentClientCert != "" && config.KeylimeAgentClientKey != "" {
		clientCert, err := tls.LoadX509KeyPair(config.KeylimeAgentClientCert, config.KeylimeAgentClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
		log.Debug("Loaded client certificate", "cert", config.KeylimeAgentClientCert, "key", config.KeylimeAgentClientKey)
	}

	// Create HTTP client with TLS configuration
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

func validatePluginConfig(c *Config) error {
	// validate host and port settings, or set to defaults if empty
	if c.KeylimeAgentHost == "" {
		c.KeylimeAgentHost = "127.0.0.1"
	}

	if c.KeylimeAgentPort == "" {
		c.KeylimeAgentPort = "9002"
	}

	// check if port is an integer between 0 and 65535
	portNum, err := strconv.Atoi(c.KeylimeAgentPort)
	if err != nil {
		return errors.New("keylime_agent_port is not a number")
	}
	if portNum < 0 {
		return errors.New("keylime_agent_port is too small to be a port")
	}
	if portNum > 65535 {
		return errors.New("keylime_agent_port is too large to be a port")
	}

	// Validate TLS configuration
	if c.KeylimeAgentUseTLS {
		// Client cert and key must both be provided or both be empty
		if (c.KeylimeAgentClientCert == "") != (c.KeylimeAgentClientKey == "") {
			return errors.New("both keylime_agent_client_cert and keylime_agent_client_key must be provided together")
		}
	}

	return nil
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
