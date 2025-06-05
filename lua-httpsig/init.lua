#!/usr/bin/env luajit

--[[
  Lua HTTP Signature Example for HyperBEAM
  
  This example demonstrates how to sign HTTP requests with RFC-9421 HTTP Message Signatures
  and send them to a HyperBEAM node using Lua/LuaJIT.
]]

local http = require('socket.http')
local ltn12 = require('ltn12')
local crypto = require('crypto')
local json = require('json')
local socket = require('socket')
local url = require('socket.url')
local mime = require('mime')
local ssl = require('ssl')

-- HTTP Signature Signer class
local HTTPSigSigner = {}
HTTPSigSigner.__index = HTTPSigSigner

function HTTPSigSigner:new(private_key, key_id)
    local signer = {
        private_key = private_key,
        key_id = key_id or "test-key-lua"
    }
    setmetatable(signer, self)
    return signer
end

-- Generate RSA key pair (simplified for demo)
function HTTPSigSigner:generate_rsa_key()
    -- For demo purposes, we'll use a hardcoded RSA key
    -- In production, you'd generate this properly
    local private_key = [[
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyZi5p810/Sf/3dOVKaUnADoHraKSoNxI2v711tuwaaOaVQyZ
cMTgf8v8bj1pbqWqZJ7AuaUGvnoQsGzesFewuk2Yku5mmi+J47e8qTZ9w/SgUDlX
7CIzV5na4UreUV0clV4qMoOU7pLojlkhF1AoyC/mINwOp2/qSuU1EaqxbKmSklTs
TgyoHVPMkVEwGK0qupTo5jzstmeSHVljIAUlOzJMCIoeuywTVhPpvqeXvpdocMcA
mDaUjzmtoTxEUVW90TcHWShH+tWj/D5UllDHoPJluwl/vWhTVwN+TiYEEpbUe6Yo
notJ8LdNlE/SOOG27M/3plPrQM+kis1SF7kHJQIDAQABAoIBAQCZ8vZ1q7xTyQJz
...
-----END RSA PRIVATE KEY-----
]]
    return private_key
end

-- Calculate SHA-256 hash
function HTTPSigSigner:sha256(data)
    return crypto.digest('sha256', data)
end

-- Base64 encode
function HTTPSigSigner:base64_encode(data)
    return mime.b64(data)
end

-- Calculate content digest
function HTTPSigSigner:calculate_content_digest(body)
    local hash = self:sha256(body)
    local encoded = self:base64_encode(hash)
    return string.format("sha-256=:%s:", encoded)
end

-- Parse URL components
function HTTPSigSigner:parse_url(request_url)
    local parsed = url.parse(request_url)
    local authority = parsed.host
    if parsed.port then
        authority = authority .. ":" .. parsed.port
    elseif parsed.scheme == "https" then
        authority = authority .. ":443"
    elseif parsed.scheme == "http" then
        authority = authority .. ":80"
    end
    
    local path = parsed.path or "/"
    if parsed.query then
        path = path .. "?" .. parsed.query
    end
    
    return {
        authority = authority,
        path = path,
        scheme = parsed.scheme
    }
end

-- Build signature base string
function HTTPSigSigner:build_signature_base(method, request_url, headers, body)
    local url_parts = self:parse_url(request_url)
    local components = {"@method", "@authority", "@path", "content-type"}
    
    -- Add content-digest if body is present
    local content_digest = nil
    if body and #body > 0 then
        content_digest = self:calculate_content_digest(body)
        table.insert(components, "content-digest")
    end
    
    local lines = {}
    
    -- Add component lines
    for _, component in ipairs(components) do
        if component == "@method" then
            table.insert(lines, string.format('"%s": %s', component, method))
        elseif component == "@authority" then
            table.insert(lines, string.format('"%s": %s', component, url_parts.authority))
        elseif component == "@path" then
            table.insert(lines, string.format('"%s": %s', component, url_parts.path))
        elseif component == "content-digest" then
            table.insert(lines, string.format('"%s": %s', component, content_digest))
        else
            -- Regular header
            local value = headers[component] or headers[component:gsub("-", "_")]
            if value then
                table.insert(lines, string.format('"%s": %s', component, value))
            end
        end
    end
    
    -- Add @signature-params line
    local created = os.time()
    local component_list = {}
    for _, comp in ipairs(components) do
        table.insert(component_list, string.format('"%s"', comp))
    end
    local components_str = "(" .. table.concat(component_list, " ") .. ")"
    local params = string.format(';created=%d;keyid="%s"', created, self.key_id)
    local signature_params = components_str .. params
    
    table.insert(lines, string.format('"@signature-params": %s', signature_params))
    
    return table.concat(lines, "\n"), created, content_digest
end

-- Sign data (simplified - in production use proper RSA-PSS)
function HTTPSigSigner:sign_data(data)
    -- For this demo, we'll use HMAC-SHA256 instead of RSA-PSS
    -- In production, you'd use proper RSA-PSS signing
    local signature = crypto.hmac.digest('sha256', 'demo-secret-key', data)
    return self:base64_encode(signature)
end

-- Sign HTTP request
function HTTPSigSigner:sign_request(method, request_url, headers, body)
    headers = headers or {}
    
    -- Build signature base
    local signature_base, created, content_digest = self:build_signature_base(method, request_url, headers, body)
    
    print("Signature Base:")
    print(signature_base)
    print()
    
    -- Sign the signature base
    local signature = self:sign_data(signature_base)
    
    -- Add signature headers
    local signed_headers = {}
    for k, v in pairs(headers) do
        signed_headers[k] = v
    end
    
    if content_digest then
        signed_headers["Content-Digest"] = content_digest
    end
    
    signed_headers["Signature"] = string.format("sig1=:%s:", signature)
    signed_headers["Signature-Input"] = string.format('sig1=("@method" "@authority" "@path" "content-type"%s);created=%d;keyid="%s"',
        content_digest and ' "content-digest"' or '', created, self.key_id)
    
    return signed_headers
end

-- Make HTTP request
function HTTPSigSigner:make_request(method, request_url, headers, body)
    -- Sign the request
    local signed_headers = self:sign_request(method, request_url, headers, body)
    
    print("Signed Headers:")
    for k, v in pairs(signed_headers) do
        print(string.format("  %s: %s", k, v))
    end
    print()
    
    -- Prepare request
    local response_body = {}
    local response_headers = {}
    
    -- Convert headers to proper format
    local header_list = {}
    for k, v in pairs(signed_headers) do
        table.insert(header_list, string.format("%s: %s", k, v))
    end
    
    -- Make the request
    print("Making HTTP request...")
    local result, status_code, response_headers_raw = http.request{
        url = request_url,
        method = method,
        headers = header_list,
        source = body and ltn12.source.string(body) or nil,
        sink = ltn12.sink.table(response_body)
    }
    
    if result then
        print(string.format("Response Status: %s", status_code))
        print("Response Headers:")
        for k, v in pairs(response_headers_raw or {}) do
            print(string.format("  %s: %s", k, v))
        end
        print("Response Body:")
        print(table.concat(response_body))
    else
        print(string.format("Request failed: %s", status_code))
    end
    
    return result, status_code, response_headers_raw, table.concat(response_body)
end

-- Main function
function main()
    print("=== HyperBEAM Lua HTTP Signature Example ===")
    print()
    
    -- Create signer
    print("1. Creating HTTP signature signer...")
    local signer = HTTPSigSigner:new(nil, "test-key-lua")
    print("Key ID: " .. signer.key_id)
    print()
    
    -- Request parameters
    local method = "POST"
    local request_url = "http://localhost:8734/lxGzM0c4k3d6ZJf6PnQuMRGcpwBXNen9uyn3103W41s~process@1.0/push"
    local headers = {
        ["Content-Type"] = "text/plain",
        ["Data-Protocol"] = "ao",
        ["Action"] = "Eval"
    }
    local body = "1 + 1"
    
    print("2. Request Details:")
    print(string.format("Method: %s", method))
    print(string.format("URL: %s", request_url))
    print("Headers:")
    for k, v in pairs(headers) do
        print(string.format("  %s: %s", k, v))
    end
    print(string.format("Body: %s", body))
    print()
    
    -- Make signed request
    print("3. Signing and sending request...")
    local result, status, response_headers, response_body = signer:make_request(method, request_url, headers, body)
    
    if not result then
        print("Failed to connect to HyperBEAM. Make sure it's running on localhost:8734")
    end
end

-- Check if we have required modules
local function check_dependencies()
    local required_modules = {'socket.http', 'crypto', 'json', 'mime'}
    local missing = {}
    
    for _, module in ipairs(required_modules) do
        local ok, _ = pcall(require, module)
        if not ok then
            table.insert(missing, module)
        end
    end
    
    if #missing > 0 then
        print("Missing required Lua modules:")
        for _, module in ipairs(missing) do
            print("  - " .. module)
        end
        print()
        print("Install with:")
        print("  luarocks install luasocket")
        print("  luarocks install luacrypto") 
        print("  luarocks install lua-cjson")
        return false
    end
    
    return true
end

-- Run the example
if check_dependencies() then
    main()
else
    print("Please install missing dependencies first.")
end