#!/bin/bash

BASHRC_PATH="/home/syssec/.bashrc"
CURR_DIR=$(pwd)
SGX_BIN="sgx_linux_x64_sdk_2.15.100.3.bin"
SGX_INSTALLER_URL="https://download.01.org/intel-sgx/sgx-linux/2.15/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.15.100.3.bin"
ENVIRONMENT_PATH="$CURR_DIR/sgxsdk/environment"

sudo apt update
sudo apt install build-essential python

if [[ ! -f "$SGX_BIN" ]]; then
	wget "$SGX_INSTALLER_URL"
	chmod +x "$SGX_BIN"
fi

echo "Installing SGX SDK..."
# echo yes to automatically install in current folder
yes yes | ./"$SGX_BIN" 2>&1 >/dev/null
echo "Installation complete!"


# This may leave some garbage lines if you install the SDK in different folders
# You will need to remove them manually
grep "source $ENVIRONMENT_PATH" "$BASHRC_PATH" || echo "source $ENVIRONMENT_PATH" >> $BASHRC_PATH

# Re-exec shell in order to load environment variables
exec $SHELL -i
