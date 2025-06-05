# HyperBEAM HTTP Signature Examples

This repository contains working examples of HTTP signature implementations for HyperBEAM in multiple programming languages. Each example demonstrates RFC-9421 HTTP Message Signatures with real working code that can sign and send requests to a HyperBEAM node.

## 🚀 Quick Start

1. **Start HyperBEAM** (required for all examples):
   ```bash
   cd /path/to/HyperBEAM
   rebar3 shell
   ```

2. **Choose your language** and follow the instructions below.

## 📁 Available Examples

### 🐹 Go Example (`go-httpsig/`)
**Production-ready implementation with RSA-PSS-SHA256 signing**

```bash
cd go-httpsig
go mod tidy
go run main.go
```

**Features:**
- ✅ Full RFC-9421 compliance
- ✅ RSA-PSS-SHA256 signing (production-grade)
- ✅ Real RSA key generation
- ✅ Structured field serialization
- ✅ Content digest calculation
- ✅ Direct HTTP request to HyperBEAM

### 🐍 Python Example (`python-httpsig/`)
**Dual implementation: full-featured and dependency-free**

#### Full Version (with RSA-PSS)
```bash
cd python-httpsig
pip install -r requirements.txt
python main.py
```

#### Simple Version (no dependencies)
```bash
cd python-httpsig
python simple_client.py
```

**Features:**
- ✅ Full RFC-9421 compliance (main.py)
- ✅ RSA-PSS-SHA256 + HMAC-SHA256 options
- ✅ Zero dependencies option (simple_client.py)
- ✅ Direct HTTP requests + curl generation
- ✅ Educational demo with simplified crypto

### 🌙 Lua Example (`lua-httpsig/`)
**Educational implementation with minimal dependencies**

```bash
cd lua-httpsig
./install_deps.sh  # Install luasocket, luacrypto, lua-cjson
luajit init.lua
```

Or for the simple version:
```bash
luajit simple_client.lua  # Generates curl command
```

**Features:**
- ✅ RFC-9421 format compliance
- ✅ HMAC-SHA256 signing (simplified for education)
- ✅ Pure Lua implementation available
- ✅ curl command generation
- ✅ Educational/demo focus

## 🔐 What Each Example Does

All examples perform the same core workflow:

1. **Generate/Configure Keys** - RSA keys (Go/Python) or demo keys (Lua)
2. **Build Request** - POST to HyperBEAM with AO protocol headers
3. **Create Signature Base** - Following RFC-9421 format with components:
   - `@method`: POST
   - `@authority`: localhost:8734
   - `@path`: /process-id/push
   - `content-type`: text/plain
   - `content-digest`: SHA-256 hash of body
4. **Sign Request** - Using RSA-PSS or HMAC algorithms
5. **Send to HyperBEAM** - With signature headers attached

## 📋 Common Request Parameters

All examples send identical requests:

- **Method**: `POST`
- **URL**: `http://localhost:8734/lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push`
- **Headers**:
  - `Data-Protocol: ao`
  - `Action: Eval`  
  - `Content-Type: text/plain`
- **Body**: `1 + 1`

## 🔍 Generated Signature Headers

Each signed request includes:

- **`Content-Digest`**: `sha-256=:base64-hash:`
- **`Signature`**: `sig1=:base64-signature:`
- **`Signature-Input`**: `sig1=("@method" "@authority" "@path" "content-type" "content-digest");created=timestamp;keyid="key-id"`

## 🏗️ Implementation Comparison

| Feature | Go | Python (Full) | Python (Simple) | Lua (Full) | Lua (Simple) |
|---------|----|--------------|--------------------|------------|--------------|
| **Algorithm** | RSA-PSS-SHA256 | RSA-PSS-SHA256 | HMAC-SHA256 | HMAC-SHA256 | HMAC-SHA256 |
| **Dependencies** | httpsfv | requests, cryptography | None | luasocket, luacrypto | None |
| **RFC Compliance** | Full | Full | Format | Format | Format |
| **Production Ready** | ✅ | ✅ | ❌ Demo | ❌ Demo | ❌ Demo |
| **Real Keys** | ✅ | ✅ | ❌ Demo | ❌ Demo | ❌ Demo |
| **HTTP Requests** | ✅ | ✅ | ✅ | ✅ | curl only |

## 🧪 Testing with HyperBEAM

1. **Start HyperBEAM** in one terminal:
   ```bash
   cd /path/to/HyperBEAM
   rebar3 shell
   ```

2. **Run any example** in another terminal
3. **Look for successful response** indicating signature verification passed

## 🎯 Educational Value

- **Go Example**: Shows production implementation patterns
- **Python Full**: Demonstrates proper cryptographic practices  
- **Python Simple**: Teaches signature concepts without dependencies
- **Lua Examples**: Minimal implementations for learning

## 🔗 RFC-9421 Resources

- [RFC-9421 HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421)
- [Structured Fields RFC-8941](https://datatracker.ietf.org/doc/html/rfc8941)

## 🛠️ Troubleshooting

**Common Issues:**
- **Connection refused**: Make sure HyperBEAM is running on localhost:8734
- **Signature verification failed**: Check that your implementation matches RFC-9421 format
- **Missing dependencies**: Follow installation instructions for each language

**For curl-based testing:**
- Copy generated curl commands from simple examples
- Verify all headers are properly formatted
- Check that base64 encoding is correct

## 📝 Next Steps

1. **Choose an example** that matches your tech stack
2. **Understand the signature process** by reading the code
3. **Adapt to your use case** by modifying request parameters
4. **Implement production features** like proper key management and error handling