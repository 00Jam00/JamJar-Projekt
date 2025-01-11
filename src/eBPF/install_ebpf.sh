#!/bin/bash

# Color variables
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if script is run with sudo or as root
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}[!] Script must be run with sudo or as root. Exiting...${NC}"
    exit 1
fi

# Check system version
current_version=$(lsb_release -r | awk '{print $2}')
required_version="22.04"

if [ "$current_version" != "$required_version" ]; then
    read -p "This script is intended for Ubuntu $required_version. Do you want to continue anyway? (y/N): " continue_update
    if [[ "$continue_update" != "y" && "$continue_update" != "Y" ]]; then
        echo -e "${RED}[!] Aborted${NC}"
        exit 1
    fi
fi

# Update the system
echo -e "${YELLOW}[...] Updating system${NC}"
apt-get update -y
echo -e "${GREEN}[+] Update done${NC}\n"

# Install requirements
echo -e "${YELLOW}[...] Installing requirements${NC}"
apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf
echo -e "${GREEN}[+] Requirements installed${NC}\n"

# Get release into /opt
echo -e "${YELLOW}[...] Getting BCC release into /opt${NC}"
wget https://github.com/iovisor/bcc/releases/download/v0.30.0/bcc-src-with-submodule.zip
unzip bcc-src-with-submodule.zip -d /opt/
rm bcc-src-with-submodule.zip

# Navigate to the build directory
echo -e "${YELLOW}[...] Building BCC${NC}"
mkdir -p /opt/bcc/build
cd /opt/bcc/build

echo -e "${YELLOW}[...] Building - This can take a while!${NC}"
# Run cmake and make
cmake ..
make
sudo make install

# Build python3 binding
echo -e "${YELLOW}[...] Building python3 binding${NC}"
cmake -DPYTHON_CMD=python3 ..
pushd src/python/
make
sudo make install
popd

# move bcc to python
mkdir /usr/lib/python3/dist-packages/bcc/
cp -r /opt/bcc/build/src/python/bcc-python3/bcc/* /usr/lib/python3/dist-packages/bcc/

echo -e "${GREEN}[+] BCC installation complete${NC}"
