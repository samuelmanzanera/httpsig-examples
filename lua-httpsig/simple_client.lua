#!/usr/bin/env luajit

--[[
  Simple Lua HTTP Signature Example for HyperBEAM
  
  This is a simplified version that uses basic HTTP without external dependencies
  to demonstrate the HTTP signature concepts.
]]

-- Simple HTTP signature implementation
local HTTPSigSigner = {}
HTTPSigSigner.__index = HTTPSigSigner

function HTTPSigSigner:new(key_id)
    local signer = {
        key_id = key_id or "test-key-lua"
    }
    setmetatable(signer, self)
    return signer
end

-- Simple SHA-256 hash (demo implementation)
function HTTPSigSigner:sha256(data)
    -- This is a simplified hash for demo purposes
    -- In production, use a proper crypto library
    local hash = 0
    for i = 1, #data do
        hash = ((hash * 31) + string.byte(data, i)) % 2147483647
    end
    return string.format("%08x", hash)
end

-- Simple base64 encode
function HTTPSigSigner:base64_encode(data)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

-- Calculate content digest
function HTTPSigSigner:calculate_content_digest(body)
    local hash = self:sha256(body)
    local encoded = self:base64_encode(hash)
    return string.format("sha-256=:%s:", encoded)
end

-- Parse URL components
function HTTPSigSigner:parse_url(request_url)
    local scheme, authority, path = request_url:match("^(https?)://([^/]+)(.*)$")
    if not scheme then
        error("Invalid URL: " .. request_url)
    end
    
    -- Add default port if not specified
    if not authority:match(":%d+$") then
        if scheme == "https" then
            authority = authority .. ":443"
        else
            authority = authority .. ":80"
        end
    end
    
    if path == "" then
        path = "/"
    end
    
    return {
        scheme = scheme,
        authority = authority,
        path = path
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
            local value = headers[component] or headers[component:gsub("-", "_")] or headers[component:gsub("^%l", string.upper)]
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

-- Simple HMAC-SHA256 (demo implementation)
function HTTPSigSigner:hmac_sha256(key, data)
    -- This is a very simplified HMAC for demo purposes
    -- In production, use a proper crypto library
    local combined = key .. data
    return self:sha256(combined)
end

-- Sign data
function HTTPSigSigner:sign_data(data)
    local signature = self:hmac_sha256("demo-secret-key", data)
    return self:base64_encode(signature)
end

-- Generate curl command for the signed request
function HTTPSigSigner:generate_curl_command(method, request_url, headers, body)
    -- Build signature base
    local signature_base, created, content_digest = self:build_signature_base(method, request_url, headers, body)
    
    print("Signature Base:")
    print(signature_base)
    print()
    
    -- Sign the signature base
    local signature = self:sign_data(signature_base)
    
    -- Build curl command
    local curl_parts = {"curl", "-X", method}
    
    -- Add headers
    for k, v in pairs(headers) do
        table.insert(curl_parts, "-H")
        table.insert(curl_parts, string.format('"%s: %s"', k, v))
    end
    
    -- Add signature headers
    if content_digest then
        table.insert(curl_parts, "-H")
        table.insert(curl_parts, string.format('"Content-Digest: %s"', content_digest))
    end
    
    table.insert(curl_parts, "-H")
    table.insert(curl_parts, string.format('"Signature: sig1=:%s:"', signature))
    
    table.insert(curl_parts, "-H")
    local sig_input = string.format('sig1=("@method" "@authority" "@path" "content-type"%s);created=%d;keyid="%s"',
        content_digest and ' "content-digest"' or '', created, self.key_id)
    table.insert(curl_parts, string.format('"Signature-Input: %s"', sig_input))
    
    -- Add body if present
    if body and #body > 0 then
        table.insert(curl_parts, "-d")
        table.insert(curl_parts, string.format('"%s"', body:gsub('"', '\\"')))
    end
    
    -- Add URL
    table.insert(curl_parts, string.format('"%s"', request_url))
    
    return table.concat(curl_parts, " ")
end

-- Main function
function main()
    print("=== HyperBEAM Lua HTTP Signature Example (Simple) ===")
    print()
    
    -- Create signer
    print("1. Creating HTTP signature signer...")
    local signer = HTTPSigSigner:new("test-key-lua")
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
    
    -- Generate signed curl command
    print("3. Generating signed curl command...")
    local curl_command = signer:generate_curl_command(method, request_url, headers, body)
    
    print()
    print("Generated curl command:")
    print("=" .. string.rep("=", 50))
    print(curl_command)
    print("=" .. string.rep("=", 50))
    print()
    print("Copy and paste the above curl command to test the signed request!")
    print("Make sure HyperBEAM is running on localhost:8734")
end

-- Run the example
main()