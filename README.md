# GoCertMITM - TLS Certificate Validation Testing Tool

GoCertMITM is a security testing tool for identifying TLS certificate validation vulnerabilities in applications and systems. It acts as a man-in-the-middle proxy that can test various certificate validation scenarios.

## Features

- **Multiple Testing Methodologies**: Test applications against different certificate validation vulnerabilities:
  1. **Self-signed certificates**: Tests if clients accept certificates signed by themselves
  2. **Replaced key certificates**: Tests if clients verify the certificate's public key
  3. **Real certificates**: Tests if clients accept valid certificates for different domains
  4. **Real certificates as CA**: Tests if clients accept certificates signed by valid but unauthorized CAs
  5. **Compromised CA (eMudhra)**: Tests if clients still trust a CA whose signing keys were publicly disclosed (see https://emudhra.we-have-a-problem.com/)

- **Network Configuration**: Automatically configures the network to intercept connections:
  - Acts as a network gateway for client devices
  - Uses iptables to redirect HTTPS traffic
  - Provides comprehensive testing without client modifications
  - Accepts any certificate presented by target servers (including invalid or self-signed certificates)

- **Comprehensive Logging**: Detailed logging and reporting:
  - Real-time console output for immediate feedback
  - Detailed logs of intercepted data for analysis
  - Structured storage of test results for reporting

## Installation

### Prerequisites

- Go 1.27 or higher
- iptables (for traffic redirection)
- Root/sudo privileges (for network configuration)

### Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/gocertmitm/gocertmitm.git
   cd gocertmitm
   ```

2. Build the application:
   ```
   make build
   ```

3. Run tests:
   ```
   make test
   ```

### Docker

You can also run GoCertMITM using Docker:

1. Build the Docker image:
   ```
   make docker-build
   ```

2. Run the Docker container:
   ```
   make docker-run
   ```

## Usage

### Basic Usage

```
./certmitm -listen :8080 -listens :8443 -verbose
```

### Command-Line Options

- `-listen`: Address to listen on for HTTP proxy (default: ":8080")
- `-listens`: Address to listen on for HTTPS proxy (default: ":8443")
- `-verbose`: Enable verbose logging (operational details)
- `-debug`: Enable debug logging (developer information)
- `-certdir`: Directory to store generated certificates (default: "./certs")
- `-logdir`: Directory to store logs (default: "./logs")
- `-payloaddir`: Directory to store request/response payloads (default: "./payloads")
- `-savepayloads`: Enable saving of request/response payloads (default: true)
- `-retryseconds`: Seconds to wait before retesting a domain (default: 86400)
- `-testtype`: Test type to start with (default: "self-signed")
  - `self-signed`: Test if clients accept self-signed certificates (Type 0)
  - `replaced-key`: Test if clients verify the certificate's public key (Type 1)
  - `real-cert`: Test if clients accept valid certificates for different domains (Type 2)
  - `real-ca`: Test if clients accept certificates signed by valid but unauthorized CAs (Type 3)
  - `emudhra`: Test if clients trust the publicly compromised eMudhra CA (Type 4)
  - When auto-testing is disabled, only this test type will be used
  - When auto-testing is enabled, this test type will be tried first, followed by the others
- `-emudhra-chain`: Which compromised eMudhra chain variant to serve (default: "both")
  - `modern`: chain via `emSign Root TLS CA - G3` (trusted by all modern trust stores)
  - `old`: chain cross-signed by `AAA Certificate Services` (frozen pre-2021 trust stores)
  - `both`: serve both variants with the modern one first; OpenSSL-style clients only build the first path
- `-autotest`: Automatically test all methods for each domain (default: true)
  - When enabled, the tool will try each test method for each domain until one succeeds
  - If all tests fail, the tool will provide a direct tunnel to the target server
  - Results are cached per domain, so successful tests are remembered
  - The test order is determined by the `-testtype` flag, with the specified type tried first
- `-maxattempts`: Maximum number of attempts for each test type before moving to the next test (default: 1)
  - Increase this value if you want to retry a test type multiple times before moving on
  - Higher values can be useful for unstable connections or intermittent failures
  - Setting to 1 ensures the tool moves quickly through test types

### Network Setup

To use GoCertMITM as a man-in-the-middle proxy, you need to:

1. Configure the tool as a network gateway
2. Redirect HTTPS traffic to the proxy
3. Configure client devices to use the proxy as their gateway

#### Using the Firewall Setup Scripts

For the Direct Tunnel mechanism to work correctly, the traffic redirection must be done on the same host where the proxy is running. We provide scripts to set up and tear down the necessary firewall rules:

```bash
# Set up firewall rules to intercept traffic from a specific IP (default: 192.168.82.118)
sudo ./scripts/setup_firewall.sh --target 192.168.82.118

# For more options, use the help flag
sudo ./scripts/setup_firewall.sh --help

# Start the proxy on port 9900
./certmitm -listens :9900 -verbose

# When done, tear down the firewall rules (use the same target IP if customized)
sudo ./scripts/teardown_firewall.sh --target 192.168.82.118
```

The setup script:
- Enables IP forwarding
- Saves the original iptables rules for restoration
- Sets up DNAT (Destination NAT) to redirect port 443 traffic from a specific IP to localhost:9900
- Configures IP masquerading for proper transparent proxying
- Ensures all traffic flows normally except for port 443 traffic from the target IP
- Adds connection marking for proper routing
- Allows customization of the target IP, proxy port, and proxy IP

The teardown script:
- Restores the original iptables rules
- Restores the original IP forwarding setting
- Cleans up any temporary files created during setup
- Accepts the same parameters as the setup script for consistency

**Note**: These scripts require root privileges to modify system settings. The target IP should be the IP address of the device whose traffic you want to intercept (e.g., the WAN side of an OpenWRT router). The setup script automatically detects your primary network interface for proper configuration.

### Installing the CA Certificate

For proper testing, you need to install the GoCertMITM CA certificate on client devices:

#### On Windows

1. Copy the `ca.crt` file to the client device
2. Double-click the certificate file
3. Select "Install Certificate"
4. Select "Current User" and click "Next"
5. Select "Place all certificates in the following store"
6. Click "Browse" and select "Trusted Root Certification Authorities"
7. Click "Next" and then "Finish"

#### On macOS

1. Copy the `ca.crt` file to the client device
2. Double-click the certificate file to open it in Keychain Access
3. Add the certificate to the System keychain
4. Find the certificate in the list, double-click it
5. Expand the "Trust" section
6. Change "When using this certificate" to "Always Trust"
7. Close the window and enter your password to confirm

#### On iOS

1. Email the `ca.crt` file to the device or host it on a web server
2. Open the file on the device
3. Follow the prompts to install the profile
4. Go to Settings > General > About > Certificate Trust Settings
5. Enable full trust for the GoCertMITM root certificate

#### On Android

1. Copy the `ca.crt` file to the device
2. Go to Settings > Security > Install from storage
3. Select the certificate file
4. Follow the prompts to install the certificate

#### On Linux

1. Copy the `ca.crt` file to `/usr/local/share/ca-certificates/`
2. Run `sudo update-ca-certificates`

#### For Firefox

Firefox uses its own certificate store:

1. Open Firefox
2. Go to Options/Preferences
3. Search for "certificates"
4. Click "View Certificates"
5. Go to the "Authorities" tab
6. Click "Import" and select the `ca.crt` file
7. Check "Trust this CA to identify websites" and click "OK"

### Certificate Requirements

GoCertMITM manages most certificate operations automatically, but certain tests require specific files:

#### Default Certificate Storage

By default, all certificates are stored in the `./certs` directory (configurable with the `-certdir` flag):

```
./certs/
  ├── ca.crt                # The GoCertMITM root CA certificate (auto-generated on first run)
  ├── ca.key                # The GoCertMITM root CA private key (auto-generated on first run)
  ├── self-signed/          # Self-signed certificates
  │   └── example.com/      # Domain-specific directory
  │       ├── cert.pem      # Generated certificate
  │       └── key.pem       # Private key
  ├── replaced-key/         # Replaced key certificates
  │   └── example.com/
  │       ├── cert.pem
  │       └── key.pem
  ├── real/                 # Real certificates for different domains
  │   └── example.com/
  │       ├── cert.pem
  │       ├── fullchain.pem
  │       └── key.pem
  ├── real-ca/              # Real certificates used as CAs
  │   └── example.com/
  │       ├── cert.pem
  │       └── key.pem
  └── emudhra/              # Compromised CA (eMudhra) certificates, full chain
      └── example.com/
          ├── cert.pem      # Leaf plus the served compromised CA chain
          └── key.pem
```

- The root CA certificate and key are automatically generated on first run if they don't exist
- You should install the `ca.crt` file as a trusted root CA on test devices to avoid certificate warnings
- All generated certificates are cached in memory during runtime and saved to disk for reuse
- Certificates are organized by test type and domain for efficient retrieval
- The eMudhra test type needs no preparation: the compromised CA chain is embedded in the binary and validated at startup

#### Test-Specific Requirements

1. **Self-signed Certificates Test**:
   - No additional files required
   - Certificates are generated dynamically during testing

2. **Replaced Key Certificates Test**:
   - No additional files required
   - Certificates are generated dynamically during testing

3. **Real Certificates Test**:
   - Requires at least one valid certificate to be used in testing
   - Place these certificates in the following structure:
   ```
   ./certs/real/
     ├── example.com/
     │   ├── cert.pem       # Leaf certificate for example.com
     │   ├── fullchain.pem  # Full certificate chain (leaf + intermediates)
     │   └── key.pem        # Private key for example.com certificate
     └── other-domain.com/
         ├── cert.pem       # Leaf certificate for other-domain.com
         ├── fullchain.pem  # Full certificate chain (leaf + intermediates)
         └── key.pem        # Private key for other-domain.com certificate
   ```
   - The `fullchain.pem` file is strongly recommended and should contain the complete certificate chain
   - If `fullchain.pem` is not available, the tool will fall back to using `cert.pem`
   - When a client connects to a domain, the tool will:
     1. First try to use a real certificate for that specific domain if available
     2. If no certificate exists for that domain, it will use any available real certificate
     3. If no real certificates are found at all, it falls back to using a CA-signed certificate
   - Only one real certificate is required for testing, regardless of how many domains you're testing
   - The tool supports both PKCS1 and PKCS8 private key formats
   - Certificate and key files must be in PEM format

4. **Real Certificates as CA Test**:
   - Requires valid certificates to be used as unauthorized CAs
   - Place these certificates in the following structure:
   ```
   ./certs/ca/
     ├── example-ca.com/
     │   ├── cert.pem     # Valid certificate to be used as CA
     │   └── key.pem      # Private key for the certificate
     └── other-ca.com/
         ├── cert.pem     # Valid certificate to be used as CA
         └── key.pem      # Private key for the certificate
   ```
   - When a client connects, the tool will use the specified certificate as a CA to sign the generated certificate
   - If no CA certificate is found for the specified domain, it falls back to using the default CA

5. **Compromised CA (eMudhra) Test**:
   - No additional files required
   - The publicly disclosed eMudhra chain is embedded in the binary and validated against the published root certificates at startup
   - Use `-emudhra-chain` (modern/old/both) to select which compromised chain variant is served

#### Certificate Format

All certificates and keys should be in PEM format:
- Certificates should begin with `-----BEGIN CERTIFICATE-----`
- Private keys should begin with `-----BEGIN PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`

#### Obtaining Certificates for Testing

For testing purposes, you can:
1. Use self-signed certificates (automatically generated)
2. Use certificates from your own domains
3. Export certificates from browsers for domains you control
4. Use test/development certificates from services like Let's Encrypt

**Note**: Only use certificates for domains you control or have permission to test. Using certificates for unauthorized domains may violate terms of service and legal regulations.

#### Creating the Certificate Directory Structure

To set up the required directory structure for certificates, you can use the provided setup script:

```bash
# Run the setup script
./scripts/setup_cert_dirs.sh
```

Or manually create the directories:

```bash
# Create the main certificate directory
mkdir -p certs

# Create directories for real certificates
mkdir -p certs/real/example.com
mkdir -p certs/real/other-domain.com

# Create directories for CA certificates
mkdir -p certs/ca/example-ca.com
mkdir -p certs/ca/other-ca.com
```

Then place your certificate files in the appropriate directories as described above.

## Testing Methodology

GoCertMITM implements four main testing approaches to identify different types of certificate validation vulnerabilities. The tool can automatically try all methods for each domain until one succeeds, or you can manually select a specific test type:

### 1. Self-signed Certificates

This test determines if clients accept certificates that are signed by themselves rather than by a trusted Certificate Authority (CA).

**How it works:**
- GoCertMITM generates a certificate where the issuer and subject are identical
- The certificate is signed using its own private key
- This certificate is presented to the client during the TLS handshake

**Security implications:**
- Clients that accept self-signed certificates bypass a fundamental security check in the PKI system
- Attackers can easily generate self-signed certificates for any domain
- This vulnerability allows for trivial man-in-the-middle attacks without needing access to trusted CAs

**Common vulnerable scenarios:**
- Development environments with security checks disabled
- Applications with improper certificate validation
- Applications with "accept all certificates" options enabled

### 2. Replaced Key Certificates

This test verifies if clients properly validate the public key in certificates, detecting key mismatches between the expected and presented certificates.

**How it works:**
- GoCertMITM obtains or generates a valid certificate chain for a domain
- It then replaces the public key in the certificate with a different one
- The modified certificate is signed by the GoCertMITM CA
- This certificate is presented to the client during the TLS handshake

**Security implications:**
- Clients that don't verify public keys are vulnerable to attacks where an attacker has compromised a private key
- Even if certificate pinning is implemented, not checking the public key renders this protection ineffective
- Allows attackers to use stolen certificates with their own private keys

**Common vulnerable scenarios:**
- Applications with incomplete certificate pinning implementations
- Custom TLS implementations that don't verify all certificate properties
- Mobile applications with simplified certificate validation

### 3. Real Certificates for Different Domains

This test checks if clients properly validate that the certificate's domain matches the domain they're connecting to.

**How it works:**
- GoCertMITM presents a valid certificate for domain A when the client is connecting to domain B
- The certificate is completely valid and trusted, but for the wrong domain
- This tests the client's domain validation logic

**Security implications:**
- Clients that accept certificates for different domains are vulnerable to domain confusion attacks
- Attackers with a valid certificate for one domain could intercept traffic for another domain
- This bypasses the domain-specific protection provided by the PKI system

**Common vulnerable scenarios:**
- Applications that only check certificate validity but not the domain
- Misconfigured hostname verification
- Applications with wildcard certificate validation issues

### 4. Real Certificates as CA

This test determines if clients accept certificates signed by valid but unauthorized Certificate Authorities.

**How it works:**
- GoCertMITM uses a valid certificate from a legitimate website as if it were a CA
- It then generates and signs new certificates using this "CA"
- These certificates are presented to clients during the TLS handshake

**Security implications:**
- Clients that accept any valid certificate as a CA undermine the entire CA trust model
- Attackers who obtain any valid certificate could generate certificates for any domain
- This vulnerability effectively breaks the hierarchical trust model of PKI

**Common vulnerable scenarios:**
- Applications with improper CA validation
- Custom certificate stores with incorrect trust settings
- Applications that don't properly validate the certificate chain

### 5. Compromised CA (eMudhra)

This test determines if clients still trust a certificate authority whose signing keys were publicly compromised.

**Background:** The private keys of eight eMudhra intermediate CA certificates were publicly disclosed on 2026-10-20 because the keys were incorrectly generated and can be recovered from the certificates themselves. Root programs and trust stores have removed the intermediates (see https://emudhra.we-have-a-problem.com/), but many clients do not consume revocation information and only stop trusting the intermediates after a software update. mitmproxy shipped this as an option in PR #8500.

**How it works:**
- GoCertMITM signs generated leaf certificates with the publicly disclosed eMudhra "EM OV TLS CA - G3C" intermediate CA key
- The full compromised CA chain is served in the handshake, exactly as eMudhra's infrastructure would
- The certificates are indistinguishable from legitimately issued ones for clients whose trust store still contains the affected roots

**Chain selection:** The compromised intermediate chains to two different trusted roots. Use `-emudhra-chain` to select which variant is served:
- `modern` (default is `both`): chain via `emSign Root TLS CA - G3`, cross-signed by `emSign ECC Root CA - G3` — present in all modern trust stores
- `old`: chain cross-signed by Sectigo's `AAA Certificate Services` — present in older or frozen pre-2021 trust stores (mirrors mitmproxy's `--emudhra-old`)
- `both` (default): serve both variants; OpenSSL-style clients only consider the first path, so the modern variant is served first

```bash
# Explicit eMudhra test type
./certmitm -testtype emudhra

# Serve only the AAA Certificate Services cross-sign for frozen clients
./certmitm -testtype emudhra -emudhra-chain old
```

The compromised CA material is embedded in the binary (validated against the disclosed root certificates at startup) and is publicly available; it does not require any file setup on disk.

**Security implications:**
- Clients that accept these certificates validate signatures correctly but have not received key-removal updates, demonstrating outdated trust store maintenance
- Outside the browser ecosystem, most TLS clients perform no revocation checks and do not enforce Certificate Transparency, both of which would have mitigated this compromise

**Common vulnerable scenarios:**
- Appliances, embeddable SDKs, and long-lived server images with static trusted CA lists
- Clients that skip intermediate revocation checking (OneCRL/CRLite/CRLSets are browser-specific)
- Frozen pre-2021 trust stores that still trust `AAA Certificate Services`

These five testing approaches comprehensively cover the most common certificate validation vulnerabilities while keeping the testing process efficient. By testing against these specific scenarios, GoCertMITM can identify weaknesses in TLS implementations that could be exploited by attackers to perform man-in-the-middle attacks.

**Operator note:** tests 2 and 5 produce certificates that a vulnerable client cannot distinguish from legitimate traffic. Only run GoCertMITM against systems you are authorized to test; verifying a "successful MITM" means intercepting someone — in authorized testing, that's the point, and the results are what you are there to measure.

### Automatic Testing

When auto-testing is enabled (the default), GoCertMITM will:

1. Track each domain that clients attempt to connect to
2. Try each test method in sequence until one succeeds
3. Remember successful tests for each domain
4. Provide a direct tunnel if all tests fail

The testing process works as follows:

1. When a client first connects to a domain, the tool starts with the test type specified by the `-testtype` flag
2. If the client accepts the certificate (successful MITM), the tool remembers this for future connections
3. If the client rejects the certificate (TLS handshake failure), the tool:
   - Detects the handshake error and extracts the domain name
   - Records the failure for the current test type
   - Automatically moves to the next test type
   - Logs the progression through test types
   - Ensures IP addresses are not mistakenly treated as domains
4. This process continues until either:
   - A test succeeds (vulnerability found)
   - All tests fail (secure client)
5. If all tests fail, subsequent connections to the same domain will use a direct tunnel

The tool tracks failed handshakes per domain and test type, ensuring that it doesn't repeatedly try tests that have already failed. This allows it to efficiently progress through the test types until it finds a vulnerability or determines that the client is secure.

Results are cached per domain, so successful tests are remembered for future connections to the same domain.

## Logging and Reporting

### General Logging

The logging system provides:

- Real-time console output for immediate feedback
- Detailed logs of intercepted data for analysis
- Structured storage of test results for reporting

#### Log Levels

GoCertMITM uses four distinct log levels to provide appropriate information for different use cases:

- **ERROR**: Critical issues that affect functionality (always displayed)
- **INFO**: Important operational information (always displayed)
- **VERBOSE**: Detailed operational information (enabled with `-verbose`)
- **DEBUG**: Developer debugging information (enabled with `-debug`)

You can control the verbosity of logging with command-line flags:

```bash
# Default logging (ERROR and INFO only)
./certmitm

# Enable verbose logging for operational details
./certmitm -verbose

# Enable debug logging for developer information
./certmitm -debug

# Enable both verbose and debug logging
./certmitm -verbose -debug
```

### Payload Logging

GoCertMITM can save the full request and response payloads for each intercepted connection:

- Each target domain gets its own directory under the payload directory
- Request and response bodies are saved as separate files
- Metadata files contain headers and other information
- Timestamps and client IPs are included in filenames for easy tracking
- Works with all certificate testing methods, including self-signed certificates

#### Payload Directory Structure

```
./payloads/
  ├── example.com/                           # Domain-specific directory
  │   ├── req_20230601_120000.000_192.168.1.2.meta   # Request metadata
  │   ├── req_20230601_120000.000_192.168.1.2.body   # Request body
  │   ├── resp_20230601_120000.000_192.168.1.2.meta  # Response metadata
  │   └── resp_20230601_120000.000_192.168.1.2.body  # Response body
  └── other-domain.com/                      # Another domain
      ├── req_20230601_120500.000_192.168.1.2.meta
      ├── req_20230601_120500.000_192.168.1.2.body
      ├── resp_20230601_120500.000_192.168.1.2.meta
      └── resp_20230601_120500.000_192.168.1.2.body
```

#### Metadata Files

Metadata files contain important information about the request or response:

- Timestamp
- Client IP address
- HTTP method (for requests)
- Status code (for responses)
- Host and path
- All headers
- Body size and filename (if body exists)

#### Enabling/Disabling Payload Logging

Payload logging is enabled by default but can be disabled:

```bash
# Disable payload logging
./certmitm -savepayloads=false

# Change payload directory
./certmitm -payloaddir=/path/to/payloads
```

#### Setting Up Payload Directories

You can use the provided script to set up the initial payload directory structure:

```bash
# Run the setup script
./scripts/setup_payload_dirs.sh
```

This will create the base directory structure. Additional domain directories will be created automatically as needed during operation.

## Development Roadmap

### Short-term Tasks
- Add support for additional certificate validation tests
- Improve error handling for edge cases
- Enhance documentation with more examples
- Add support for upstream proxies

### Medium-term Goals
- Develop a web interface for easier result analysis
- Add support for automated testing of specific applications
- Implement pre-generation of certificates for faster testing
- Create reporting templates for vulnerability disclosure

### Long-term Vision
- Expand to support additional protocols beyond HTTPS
- Develop plugins for popular security testing frameworks
- Create a database of known vulnerable applications
- Provide automated remediation recommendations

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by the need for better TLS security testing tools
- Thanks to all contributors and the security research community