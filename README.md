# SPIRE Keylime Plugin

This repository contains an experimental agent and server plugins for [SPIRE](https://github.com/spiffe/spire) to allow Keylime node attestation.

## Menu

- [Quick start](#quick-start)
- [How it Works](#how-it-works)
- [Building](#building)
- [Contributions](#contributions)
- [License](#license)
- [Code of Conduct](#code-of-conduct)
- [Security Vulnerability Reporting](#security-vulnerability-reporting)

## Quick Start

Before starting, create a running SPIRE deployment and add the following configuration to the agent and server:

### Agent Configuration

```hcl
NodeAttestor "keylime" {
	plugin_cmd = "/path/to/plugin_cmd"
	plugin_checksum = "sha256 of the plugin binary"
	plugin_data {
        keylime_agent_host = "192.168.0.52"
        keylime_agent_port = "9005"
	}
}
```

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| keylime_agent_host | string | no | hostname of the keylime agent | 127.0.0.1 |
| keylime_agent_port | string | no | port number of the keylime agent | 9002 |

### Server Configuration

```hcl
NodeAttestor "keylime" {
	plugin_cmd = "/path/to/plugin_cmd"
	plugin_checksum = "sha256 of the plugin binary"
	plugin_data {
        keylime_verifier_host = "192.168.0.53"
        keylime_verifier_port = "8888"
	}
}
```

| key | type | required | description | default |
|:----|:-----|:---------|:------------|:--------|
| keylime_verifier_host | string | no | hostname of the verifier server | 127.0.0.1 |
| keylime_verifier_port | string | no | port number of the verifier server | 8881 |

## How it Works

The plugin uses Keylime as a source of truth not only for node identity, but also for attested node integrity. The plugin operates as follows:

1. The SPIRE agent plugin queries the `/info` API on the Keylime agent to get information like the Keylime UUID for this node
1. The SPIRE agent sends a node attesation request to the SPIRE server
1. The SPIRE server plugin verifies that the node is registered in Keylime and is passing Keylime attestation
1. The SPIRE server plugin creates an attestation challenge request with a nonce to the SPIRE agent plugin
1. The SPIRE agent plugin requests a signed identity quote from the Keylime agent with the given nonce
1. The Keylime agent creates a signed quote with the TPM's attestation key (AK) and sends it back to the SPIRE agent plugin
1. The SPIRE agent plugin sends this signed quote back to the SPIRE server plugin
1. The SPIRE server plugin validates this quote with the Keylime verifier
1. The SPIRE server plugin sends back a SPIFFE ID and SVID (and supported selectors) to the SPIRE agent plugin

For more info on how Keylime attestation works see [keylime.dev](keylime.dev).

## Supported Selectors

TBD: Selector support is coming soon

## Building

To build this plugin on Linux, run `make build`.

## Contributions

We welcome issue reports [here](../../issues); be sure to choose the proper issue template for your issue, so that we can be sure you're providing the necessary information.

Before sending a [Pull Request](../../pulls), please make sure you read our
[Contribution Guidelines](https://github.com/keylime/keylime/blob/master/CONTRIBUTING.md).

## License

Please read the [LICENSE](LICENSE) file.

## Code of Conduct

This project has adopted a [Code of Conduct](https://github.com/keylime/keylime/blob/master/CODE_OF_CONDUCT.md).
If you have any concerns about the Code, or behavior which you have experienced in the project, please
contact the keylime project.

## Security Considerations

Keylime leverages a node's TPM device for identity attestation and the Keylime SPIRE agent plugin communicates directly with the Keylime agent. This is necessary to provide flexibility (if Keylime adds other attestation models) and avoid conflicts (multiple processes trying to "own" the TPM device). But it is possible for a rogue process to spoof the Keylime agent and talk to a different TPM device (maybe on another server).

In practice, this issue is mitigated by the SPIRE attestor using Trust on First Use (or TOFU) semantics. A Keylime agent spoof would need to connect to another node with a valid TPM that is also registered in Keylime and passing the same Keylime attestation policies as the target node, but is not enrolled in SPIRE identity attestation. Otherwise one of the two nodes would fail to acquire identities from SPIRE.

This condition is easily and quickly detectable as SPIRE Agent will fail to start, and both SPIRE Agent and SPIRE Server will log the occurrence. Such cases should be investigated as possible security incidents.

## Security Vulnerability Reporting

If you believe you have identified a security vulnerability in this project, please send email to the project team at security@keylime.groups.io, detailing the suspected issue and any methods you've found to reproduce it.

Please do NOT open an issue in the GitHub repository, as we'd prefer to keep vulnerability reports private until we've had an opportunity to review and address them.
