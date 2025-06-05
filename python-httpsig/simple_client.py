#!/usr/bin/env python3
"""
Simple Python HTTP Signature Example for HyperBEAM

This is a simplified version that uses basic HTTP without external dependencies
to demonstrate the HTTP signature concepts.
"""

import base64
import hashlib
import hmac
import time
import urllib.request
import urllib.parse
from typing import Dict, List, Tuple, Optional


class SimpleHTTPSigSigner:
    """Simple HTTP Signature Signer with minimal dependencies"""
    
    def __init__(self, key_id: str = "test-key-python-simple"):
        self.key_id = key_id
    
    def calculate_content_digest(self, body: str) -> str:
        """Calculate SHA-256 content digest"""
        hash_obj = hashlib.sha256(body.encode('utf-8'))
        digest = base64.b64encode(hash_obj.digest()).decode('ascii')
        return f"sha-256=:{digest}:"
    
    def parse_url(self, url: str) -> Dict[str, str]:
        """Parse URL into components"""
        parsed = urllib.parse.urlparse(url)
        
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
    
    def sign_hmac(self, data: bytes, secret: str = "demo-secret-key") -> bytes:
        """Sign data using HMAC-SHA256"""
        return hmac.new(
            secret.encode('utf-8'),
            data,
            hashlib.sha256
        ).digest()
    
    def generate_curl_command(self, method: str, url: str, headers: Dict[str, str], body: Optional[str] = None) -> str:
        """Generate curl command for the signed request"""
        # Build signature base
        signature_base, created, content_digest = self.build_signature_base(method, url, headers, body)
        
        print("Signature Base:")
        print(signature_base)
        print()
        
        # Sign the signature base
        signature_base_bytes = signature_base.encode('utf-8')
        signature_bytes = self.sign_hmac(signature_base_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode('ascii')
        
        # Build curl command
        curl_parts = ["curl", "-X", method]
        
        # Add original headers
        for k, v in headers.items():
            curl_parts.extend(["-H", f'"{k}: {v}"'])
        
        # Add signature headers
        if content_digest:
            curl_parts.extend(["-H", f'"Content-Digest: {content_digest}"'])
        
        curl_parts.extend(["-H", f'"Signature: sig1=:{signature_b64}:"'])
        
        # Build signature-input header
        component_names = ["@method", "@authority", "@path", "content-type"]
        if content_digest:
            component_names.append("content-digest")
        
        component_list = [f'"{comp}"' for comp in component_names]
        sig_input = f'sig1=({" ".join(component_list)});created={created};keyid="{self.key_id}"'
        curl_parts.extend(["-H", f'"Signature-Input: {sig_input}"'])
        
        # Add body if present
        if body:
            curl_parts.extend(["-d", f'"{body}"'])
        
        # Add URL
        curl_parts.append(f'"{url}"')
        
        return ' '.join(curl_parts)
    
    def make_request(self, method: str, url: str, headers: Dict[str, str], body: Optional[str] = None) -> None:
        """Make signed HTTP request using urllib"""
        # Build signature base
        signature_base, created, content_digest = self.build_signature_base(method, url, headers, body)
        
        print("Signature Base:")
        print(signature_base)
        print()
        
        # Sign the signature base
        signature_base_bytes = signature_base.encode('utf-8')
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
        
        print("Signed Headers:")
        for k, v in signed_headers.items():
            print(f"  {k}: {v}")
        print()
        
        # Make the request
        print("Making HTTP request...")
        try:
            data = body.encode('utf-8') if body else None
            req = urllib.request.Request(url, data=data, method=method)
            
            # Add headers
            for k, v in signed_headers.items():
                req.add_header(k, v)
            
            with urllib.request.urlopen(req, timeout=30) as response:
                print(f"Response Status: {response.getcode()} {response.reason}")
                print("Response Headers:")
                for k, v in response.headers.items():
                    print(f"  {k}: {v}")
                print("Response Body:")
                print(response.read().decode('utf-8'))
                
        except urllib.error.URLError as e:
            print(f"Request failed: {e}")
            print("Make sure HyperBEAM is running on localhost:8734")


def main():
    print("=== HyperBEAM Python HTTP Signature Example (Simple) ===")
    print()
    
    # Create signer
    print("1. Creating HTTP signature signer...")
    signer = SimpleHTTPSigSigner("test-key-python-simple")
    print(f"Key ID: {signer.key_id}")
    print("Signing Method: HMAC-SHA256 (demo)")
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
    
    # Generate curl command by default
    print("3. Generating signed curl command...")
    curl_command = signer.generate_curl_command(method, url, headers, body)
    
    print()
    print("Generated curl command:")
    print("=" * 60)
    print(curl_command)
    print("=" * 60)
    print()
    print("Copy and paste the above curl command to test the signed request!")
    print("Make sure HyperBEAM is running on localhost:8734")


if __name__ == "__main__":
    main()