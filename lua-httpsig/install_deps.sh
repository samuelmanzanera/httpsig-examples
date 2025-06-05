#!/bin/bash

# Install Lua dependencies for HTTP signature example

echo "Installing Lua dependencies for HTTP signature example..."

# Check if luarocks is installed
if ! command -v luarocks &> /dev/null; then
    echo "Installing luarocks..."
    if command -v brew &> /dev/null; then
        brew install luarocks
    elif command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y luarocks
    elif command -v yum &> /dev/null; then
        sudo yum install -y luarocks
    else
        echo "Please install luarocks manually for your system"
        exit 1
    fi
fi

echo "Installing required Lua modules..."

# Install required modules
luarocks install luasocket
luarocks install luacrypto  
luarocks install lua-cjson

echo "Dependencies installed successfully!"
echo "You can now run: luajit init.lua"