# Lua HTTP Signature Example for HyperBEAM

This example demonstrates how to sign HTTP requests with RFC-9421 HTTP Message Signatures and send them to a HyperBEAM node using Lua/LuaJIT.

## Features

- **RFC-9421 Inspired**: Implements HTTP Message Signatures format
- **HMAC-SHA256**: Uses HMAC-SHA256 for signing (simplified for demo)
- **Content Digest**: Automatically calculates SHA-256 content digest for request bodies
- **AO Integration**: Configured for AO protocol requests to HyperBEAM
- **Pure Lua**: Uses standard Lua libraries with minimal dependencies

## Request Parameters

The example sends a request with these specific parameters:

- **Method**: POST
- **URL**: `http://localhost:8734/lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push`
- **Headers**:
  - `Data-Protocol: ao`
  - `Action: Eval`
  - `Content-Type: text/plain`
- **Body**: `1 + 1`

## Dependencies

Install required Lua modules:

```bash
# Install LuaRocks (if not already installed)
brew install luarocks  # macOS
# or
apt-get install luarocks  # Ubuntu/Debian

# Install required modules
luarocks install luasocket
luarocks install luacrypto
luarocks install lua-cjson
```

## Usage

1. **Make sure HyperBEAM is running**:
   ```bash
   cd /Users/rakis/code/HyperBEAM
   rebar3 shell
   ```

2. **Run the Lua example**:
   ```bash
   cd examples/lua-httpsig
   luajit init.lua
   # or
   lua init.lua
   ```

## What it does

1. **Creates HTTP signature signer** with a demo key ID
2. **Builds signature base** following RFC-9421 format
3. **Signs the request** using HMAC-SHA256 (simplified)
4. **Sends signed request** to HyperBEAM
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
- `Signature`: Contains the HMAC signature
- `Signature-Input`: Contains the signature parameters and component list
- `Content-Digest`: SHA-256 hash of the request body

## Implementation Notes

### Simplified Signing
This example uses HMAC-SHA256 instead of RSA-PSS for simplicity, as proper RSA-PSS implementation in Lua requires additional native libraries. The signature format and base string generation follow RFC-9421 principles.

### Production Considerations
For production use, you would need to:
1. Implement proper RSA-PSS signing
2. Use real private keys (not demo keys)
3. Add proper error handling
4. Implement key management

## Example Output

```
=== HyperBEAM Lua HTTP Signature Example ===

1. Creating HTTP signature signer...
Key ID: test-key-lua

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
"@signature-params": ("@method" "@authority" "@path" "content-type" "content-digest");created=1234567890;keyid="test-key-lua"

Signed Headers:
  Content-Type: text/plain
  Data-Protocol: ao
  Action: Eval
  Content-Digest: sha-256=:cvzllEegH0iLEWnS10JnnP4waol3LWf+8Bi8/pVDH2g=:
  Signature: sig1=:base64_encoded_signature:
  Signature-Input: sig1=("@method" "@authority" "@path" "content-type" "content-digest");created=1234567890;keyid="test-key-lua"

Response Status: 200 OK
Response Body: {...}
```

## Comparison with Go Example

| Feature | Go Example | Lua Example |
|---------|------------|-------------|
| Signing Algorithm | RSA-PSS-SHA256 | HMAC-SHA256 (demo) |
| Dependencies | `httpsfv` library | `luasocket`, `luacrypto` |
| Key Generation | Real RSA keys | Demo/hardcoded |
| RFC-9421 Compliance | Full | Format-compliant |
| Production Ready | Yes | Demo/Educational |

The Lua example demonstrates the same HTTP signature concepts as the Go version but uses simplified cryptography for educational purposes.