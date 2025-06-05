#!/usr/bin/env python3
"""
Python HTTP Signature Example for HyperBEAM

This example demonstrates how to sign HTTP requests with RFC-9421 HTTP Message Signatures
and send them to a HyperBEAM node using Python.
"""

import base64
import hashlib
import hmac
import json
import time
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class HTTPSigSigner:
    """HTTP Signature Signer implementing RFC-9421 concepts"""
    
    def __init__(self, private_key=None, key_id: str = "test-key-python"):
        self.private_key = private_key
        self.key_id = key_id
    
    @classmethod
    def generate_rsa_key(cls) -> rsa.RSAPrivateKey:
        """Generate a new RSA private key"""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    
    def export_public_key_jwk(self, private_key: rsa.RSAPrivateKey) -> Dict:
        """Export public key in JWK format"""
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        
        def int_to_base64url(num: int) -> str:
            byte_length = (num.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(
                num.to_bytes(byte_length, 'big')
            ).decode('ascii').rstrip('=')
        
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "PS256",
            "n": int_to_base64url(public_numbers.n),
            "e": int_to_base64url(public_numbers.e)
        }
    
    def calculate_content_digest(self, body: str) -> str:
        """Calculate SHA-256 content digest"""
        hash_obj = hashlib.sha256(body.encode('utf-8'))
        digest = base64.b64encode(hash_obj.digest()).decode('ascii')
        return f"sha-256=:{digest}:"
    
    def parse_url(self, url: str) -> Dict[str, str]:
        """Parse URL into components"""
        parsed = urlparse(url)
        
        # Determine authority with port
        authority = parsed.hostname
        if parsed.port:
            authority += f":{parsed.port}"
        elif parsed.scheme == "https":
            authority += ":443"
        elif parsed.scheme == "http":
            authority += ":80"
        
        # Build path with query
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        
        return {
            "authority": authority,
            "path": path,
            "scheme": parsed.scheme
        }
    
    def build_signature_base(self, method: str, url: str, headers: Dict[str, str], body: Optional[str] = None) -> Tuple[str, int, Optional[str]]:
        """Build signature base string according to RFC-9421"""
        url_parts = self.parse_url(url)
        components = ["@method", "@authority", "@path", "content-type"]
        
        # Add content-digest if body is present
        content_digest = None
        if body:
            content_digest = self.calculate_content_digest(body)
            components.append("content-digest")
        
        lines = []
        
        # Add component lines
        for component in components:
            if component == "@method":
                lines.append(f'"{component}": {method}')
            elif component == "@authority":
                lines.append(f'"{component}": {url_parts["authority"]}')
            elif component == "@path":
                lines.append(f'"{component}": {url_parts["path"]}')
            elif component == "content-digest":
                lines.append(f'"{component}": {content_digest}')
            else:
                # Regular header (case-insensitive lookup)
                value = None
                for k, v in headers.items():
                    if k.lower() == component.lower():
                        value = v
                        break
                if value:
                    lines.append(f'"{component}": {value}')
        
        # Add @signature-params line
        created = int(time.time())
        component_list = [f'"{comp}"' for comp in components]
        components_str = f"({' '.join(component_list)})"
        params = f';created={created};keyid="{self.key_id}"'
        signature_params = components_str + params
        
        lines.append(f'"@signature-params": {signature_params}')
        
        return '\n'.join(lines), created, content_digest
    
    def sign_rsa_pss(self, data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Sign data using RSA-PSS-SHA256"""
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    
    def sign_hmac(self, data: bytes, secret: str = "demo-secret-key") -> bytes:
        """Sign data using HMAC-SHA256 (demo)"""
        return hmac.new(
            secret.encode('utf-8'),
            data,
            hashlib.sha256
        ).digest()
    
    def sign_request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str] = None, use_rsa: bool = True) -> Dict[str, str]:
        """Sign HTTP request and return headers"""
        # Build signature base
        signature_base, created, content_digest = self.build_signature_base(method, url, headers, body)
        
        print("Signature Base:")
        print(signature_base)
        print()
        
        # Sign the signature base
        signature_base_bytes = signature_base.encode('utf-8')
        
        if use_rsa and self.private_key:
            signature_bytes = self.sign_rsa_pss(signature_base_bytes, self.private_key)
        else:
            signature_bytes = self.sign_hmac(signature_base_bytes)
        
        signature_b64 = base64.b64encode(signature_bytes).decode('ascii')
        
        # Build signed headers
        signed_headers = headers.copy()
        
        if content_digest:
            signed_headers["Content-Digest"] = content_digest
        
        signed_headers["Signature"] = f"sig1=:{signature_b64}:"
        
        # Build signature-input header
        component_names = ["@method", "@authority", "@path", "content-type"]
        if content_digest:
            component_names.append("content-digest")
        
        component_list = [f'"{comp}"' for comp in component_names]
        sig_input = f'sig1=({" ".join(component_list)});created={created};keyid="{self.key_id}"'
        signed_headers["Signature-Input"] = sig_input
        
        return signed_headers
    
    def make_request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str] = None, use_rsa: bool = True) -> requests.Response:
        """Make signed HTTP request"""
        # Sign the request
        signed_headers = self.sign_request(method, url, headers, body, use_rsa)
        
        print("Signed Headers:")
        for k, v in signed_headers.items():
            print(f"  {k}: {v}")
        print()
        
        # Make the request
        print("Making HTTP request...")
        response = requests.request(
            method=method,
            url=url,
            headers=signed_headers,
            data=body,
            timeout=30
        )
        
        return response


def main():
    print("=== HyperBEAM Python HTTP Signature Example ===")
    print()
    
    # Option 1: Use RSA-PSS signing (production-like)
    print("1. Creating HTTP signature signer with RSA key...")
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        private_key = HTTPSigSigner.generate_rsa_key()
        signer = HTTPSigSigner(private_key, "test-key-python-rsa")
        use_rsa = True
        
        # Export public key JWK
        jwk = signer.export_public_key_jwk(private_key)
        print("Public Key JWK:")
        print(json.dumps(jwk, indent=2))
        print()
        
    except ImportError:
        print("Cryptography library not available, using HMAC signing...")
        signer = HTTPSigSigner(None, "test-key-python-hmac")
        use_rsa = False
    
    print(f"Key ID: {signer.key_id}")
    print(f"Signing Method: {'RSA-PSS-SHA256' if use_rsa else 'HMAC-SHA256'}")
    print()
    
    # Request parameters (same as Go and Lua examples)
    method = "POST"
    url = "http://localhost:8734/lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push"
    headers = {
        "Content-Type": "text/plain",
        "Data-Protocol": "ao",
        "Action": "Eval"
    }
    body = "1 + 1"
    
    print("2. Request Details:")
    print(f"Method: {method}")
    print(f"URL: {url}")
    print("Headers:")
    for k, v in headers.items():
        print(f"  {k}: {v}")
    print(f"Body: {body}")
    print()
    
    # Make signed request
    print("3. Signing and sending request...")
    try:
        response = signer.make_request(method, url, headers, body, use_rsa)
        
        print(f"Response Status: {response.status_code} {response.reason}")
        print("Response Headers:")
        for k, v in response.headers.items():
            print(f"  {k}: {v}")
        print("Response Body:")
        print(response.text)
        
    except requests.exceptions.ConnectionError:
        print("Failed to connect to HyperBEAM. Make sure it's running on localhost:8734")
    except Exception as e:
        print(f"Request failed: {e}")


if __name__ == "__main__":
    main()