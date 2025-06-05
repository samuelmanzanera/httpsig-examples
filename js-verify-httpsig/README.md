# Verify HTTP Signature

A Node.js utility for verifying HTTP message signatures according to the HTTP Message Signatures specification.

## Description

This project provides functionality to verify HTTP message signatures using various algorithms including HMAC-SHA256 and RSA-PSS-SHA512. It's designed to work with the HTTP Message Signatures specification and can be used to verify the authenticity of HTTP requests and responses.

## Installation

```bash
npm install
```

## Dependencies

- http-message-signatures: ^1.0.4
- node-rsa: ^1.1.1

## Features

- Support for HMAC-SHA256 signatures
- Support for RSA-PSS-SHA512 signatures
- Automatic key lookup based on signature parameters
- Verification of HTTP message signatures according to the specification

