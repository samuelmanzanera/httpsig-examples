# Go HTTP Signature Example for HyperBEAM

This example demonstrates how to sign HTTP requests with RFC-9421 HTTP Message Signatures and send them to a HyperBEAM node.

## Features

- **RFC-9421 Compliant**: Implements HTTP Message Signatures according to the official RFC
- **RSA-PSS-SHA256**: Uses RSA-PSS signature algorithm with SHA-256 hash
- **Content Digest**: Automatically calculates SHA-256 content digest for request bodies
- **Structured Fields**: Uses proper structured field serialization for signature parameters
- **AO Integration**: Configured for AO protocol requests to HyperBEAM

## Request Parameters

The example sends a request with these specific parameters:

- **Method**: POST
- **URL**: `http://localhost:8734/lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push`
- **Headers**:
  - `Data-Protocol: ao`
  - `Action: Eval`
  - `Content-Type: text/plain`
- **Body**: `1 + 1`

## Usage

1. **Install dependencies**:
   ```bash
   cd examples/go-httpsig
   go mod tidy
   ```

2. **Start HyperBEAM** (in another terminal):
   ```bash
   rebar3 shell
   ```

3. **Run the example**:
   ```bash
   go run main.go
   ```

## What it does

1. **Generates RSA key pair** for signing
2. **Creates HTTP request** with the specified AO parameters
3. **Signs the request** using RFC-9421 HTTP Message Signatures
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
- `Signature`: Contains the RSA-PSS signature
- `Signature-Input`: Contains the signature parameters and component list
- `Content-Digest`: SHA-256 hash of the request body

## Compatibility with HyperBEAM

This implementation should be compatible with HyperBEAM's HTTP signature verification because it:

- Uses standard RFC-9421 format
- Avoids HyperBEAM's custom parameters (`bundle`, `tag`)
- Uses proper structured field serialization
- Includes all required signature components
- Uses RSA-PSS-SHA256 (compatible with HyperBEAM's RSA-PSS-SHA512)

## Testing

The example will show:
1. The generated signature base string
2. All HTTP headers (including signature headers)
3. The HyperBEAM response
4. Any errors in the signing or verification process

If HyperBEAM accepts and verifies the signature, you'll see a successful AO process execution response.