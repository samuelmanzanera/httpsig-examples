# Python HTTP Signature Example for HyperBEAM

This example demonstrates how to sign HTTP requests with RFC-9421 HTTP Message Signatures and send them to a HyperBEAM node using Python.

## Features

- **RFC-9421 Compliant**: Implements HTTP Message Signatures according to the official RFC
- **Dual Signing Methods**: 
  - RSA-PSS-SHA256 (production-like, requires `cryptography` library)
  - HMAC-SHA256 (demo/educational, built-in libraries only)
- **Content Digest**: Automatically calculates SHA-256 content digest for request bodies
- **AO Integration**: Configured for AO protocol requests to HyperBEAM
- **Two Versions**: Full-featured and simple (no external dependencies)

## Request Parameters

The example sends a request with these specific parameters:

- **Method**: POST
- **URL**: `http://localhost:8734/lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push`
- **Headers**:
  - `Data-Protocol: ao`
  - `Action: Eval`
  - `Content-Type: text/plain`
- **Body**: `1 + 1`

## Installation and Usage

### Option 1: Full-featured version (with RSA-PSS)

1. **Install dependencies**:
   ```bash
   cd examples/python-httpsig
   pip install -r requirements.txt
   ```

2. **Run the example**:
   ```bash
   python main.py
   ```

### Option 2: Simple version (no dependencies)

1. **Run directly** (uses Python standard library only):
   ```bash
   python simple_client.py
   ```

## What it does

1. **Creates HTTP signature signer** with RSA or HMAC signing
2. **Builds signature base** following RFC-9421 format
3. **Signs the request** using RSA-PSS-SHA256 or HMAC-SHA256
4. **Sends signed request** to HyperBEAM or generates curl command
5. **Displays the response** from the AO process

## Key Components

### Signature Base Format
The signature base includes these components:
- `@method`: HTTP method (POST)
- `@authority`: Host and port
- `@path`: URL path and query
- `content-type`: Content type header
- `content-digest`: SHA-256 digest of body (if present)

### Generated Headers
- `Signature`: Contains the RSA-PSS or HMAC signature
- `Signature-Input`: Contains the signature parameters and component list
- `Content-Digest`: SHA-256 hash of the request body

## Comparison with Other Examples

| Feature | Go Example | Lua Example | Python Example |
|---------|------------|-------------|----------------|
| Signing Algorithm | RSA-PSS-SHA256 | HMAC-SHA256 (demo) | Both RSA-PSS & HMAC |
| Dependencies | `httpsfv` | None | `requests`, `cryptography` (optional) |
| Key Generation | Real RSA keys | Demo/hardcoded | Real RSA keys |
| RFC-9421 Compliance | Full | Format-compliant | Full |
| Production Ready | Yes | Educational | Yes (main.py) |
| Simple Version | No | Yes | Yes (simple_client.py) |

## Example Output

### Full Version (main.py)
```
=== HyperBEAM Python HTTP Signature Example ===

1. Creating HTTP signature signer with RSA key...
Public Key JWK:
{
  "kty": "RSA",
  "use": "sig", 
  "alg": "PS256",
  "n": "base64_encoded_modulus",
  "e": "AQAB"
}

Key ID: test-key-python-rsa
Signing Method: RSA-PSS-SHA256

2. Request Details:
Method: POST
URL: http://localhost:8734/lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push
Headers:
  Content-Type: text/plain
  Data-Protocol: ao
  Action: Eval
Body: 1 + 1

3. Signing and sending request...
Signature Base:
"@method": POST
"@authority": localhost:8734
"@path": /lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push
"content-type": text/plain
"content-digest": sha-256=:cvzllEegH0iLEWnS10JnnP4waol3LWf+8Bi8/pVDH2g=:
"@signature-params": ("@method" "@authority" "@path" "content-type" "content-digest");created=1234567890;keyid="test-key-python-rsa"

Signed Headers:
  Content-Type: text/plain
  Data-Protocol: ao
  Action: Eval
  Content-Digest: sha-256=:cvzllEegH0iLEWnS10JnnP4waol3LWf+8Bi8/pVDH2g=:
  Signature: sig1=:base64_encoded_signature:
  Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest");created=1234567890;keyid="test-key-python-rsa"

Response Status: 200 OK
Response Body: {...}
```

### Simple Version (simple_client.py)
```
=== HyperBEAM Python HTTP Signature Example (Simple) ===

1. Creating HTTP signature signer...
Key ID: test-key-python-simple
Signing Method: HMAC-SHA256 (demo)

3. Choose action:
  [1] Make HTTP request directly
  [2] Generate curl command

Generated curl command:
============================================================
curl -X POST -H "Content-Type: text/plain" -H "Data-Protocol: ao" -H "Action: Eval" -H "Content-Digest: sha-256=:cvzllEegH0iLEWnS10JnnP4waol3LWf+8Bi8/pVDH2g=:" -H "Signature: sig1=:base64_signature:" -H "Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest");created=1234567890;keyid="test-key-python-simple"" -d "1 + 1" "http://localhost:8734/lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push"
============================================================
```

## Testing

Make sure HyperBEAM is running:
```bash
cd /Users/rakis/code/HyperBEAM
rebar3 shell
```

Then run either version of the Python example to test HTTP signature generation and verification with HyperBEAM.