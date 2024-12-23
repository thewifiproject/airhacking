#!/bin/sh

# Purpose: Install Realtek out-of-kernel USB WiFi adapter drivers.
#
# Supports dkms and non-dkms installations.
#
# To make this file executable:
#
# $ chmod +x install-driver.sh
#
# To execute this file:
#
# $ sudo ./install-driver.sh
#
# or
#
# $ sudo sh install-driver.sh
#
# Copyright(c) 2024 Nick Morrow
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

SCRIPT_NAME="install-driver.sh"
SCRIPT_VERSION="20240314"

MODULE_NAME="8821au"
DRV_NAME="rtl8821au"
DRV_VERSION="5.12.5.2"
DRV_DIR="$(pwd)"
OPTIONS_FILE="${MODULE_NAME}.conf"

# Hardcode the kernel version you want to target: 6.11.2-amd64
KVER="6.11.2-amd64"
KARCH="$(uname -m)"

MODDESTDIR="/lib/modules/${KVER}/kernel/drivers/net/wireless/"

GARCH="$(uname -m | sed -e "s/i.86/i386/; s/ppc/powerpc/; s/armv.l/arm/; s/aarch64/arm64/; s/riscv.*/riscv/;")"

# Check to ensure sudo or su - was used to start the script
if [ "$(id -u)" -ne 0 ]; then
    echo "You must run this script with superuser (root) privileges."
    echo "Try: \"sudo ./${SCRIPT_NAME}\""
    exit 1
fi

# Check if required packages are installed
for pkg in gcc bc make; do
    if ! command -v $pkg >/dev/null 2>&1; then
        echo "A required package is not installed."
        echo "Please install the following package: $pkg"
        echo "Once the package is installed, please run \"sudo ./${SCRIPT_NAME}\""
        exit 1
    fi
done

# Check to ensure correct kernel headers are installed
if [ ! -d "/lib/modules/${KVER}/build" ]; then
    echo "Kernel headers for ${KVER} are not installed."
    echo "Please install the headers and try again."
    exit 1
fi

# Display some system information
echo ": ---------------------------"
echo ": ${SCRIPT_NAME} v${SCRIPT_VERSION}"
echo ": Kernel version: ${KVER} (kernel version)"
echo ": Kernel architecture: ${KARCH} (kernel architecture)"
echo ": Architecture to send to gcc: ${GARCH}"
echo ": ---------------------------"

# Checking for previously installed drivers
echo "Checking for previously installed drivers..."

# Remove old drivers if installed
if [ -f "${MODDESTDIR}${MODULE_NAME}.ko" ]; then
    echo "Removing a non-dkms installation: ${MODDESTDIR}${MODULE_NAME}.ko"
    rm -f "${MODDESTDIR}${MODULE_NAME}.ko"
    /sbin/depmod -a "${KVER}"
    echo "Removing ${OPTIONS_FILE} from /etc/modprobe.d"
    rm -f /etc/modprobe.d/${OPTIONS_FILE}
    echo "Removing source files from /usr/src/${DRV_NAME}-${DRV_VERSION}"
    rm -rf /usr/src/${DRV_NAME}-${DRV_VERSION}
    make clean >/dev/null 2>&1
    echo "Removal complete."
fi

# Install driver
echo "Starting installation."
echo "Installing ${OPTIONS_FILE} to /etc/modprobe.d"
cp -f ${OPTIONS_FILE} /etc/modprobe.d

# Non-DKMS installation
if ! command -v dkms >/dev/null 2>&1; then
    echo "The non-dkms installation routines are in use."
    make clean >/dev/null 2>&1
    make -j"$(nproc)"
    RESULT=$?

    if [ "$RESULT" != "0" ]; then
        echo "An error occurred during the build: ${RESULT}"
        exit $RESULT
    fi

    make install
    RESULT=$?

    if [ "$RESULT" = "0" ]; then
        make clean >/dev/null 2>&1
        echo "The driver was installed successfully."
        echo ": ---------------------------"
    else
        echo "An error occurred during installation: ${RESULT}"
        exit $RESULT
    fi
else
    # DKMS installation
    echo "The dkms installation routines are in use."
    echo "Copying source files to /usr/src/${DRV_NAME}-${DRV_VERSION}"
    cp -r "${DRV_DIR}" /usr/src/${DRV_NAME}-${DRV_VERSION}

    # Run dkms add
    dkms add -m ${DRV_NAME} -v ${DRV_VERSION} -k "${KVER}"
    RESULT=$?
    
    if [ "$RESULT" != "0" ]; then
        echo "An error occurred. dkms add error: ${RESULT}"
        exit $RESULT
    fi

    # Run dkms build
    dkms build -m ${DRV_NAME} -v ${DRV_VERSION} -k "${KVER}"
    RESULT=$?

    if [ "$RESULT" != "0" ]; then
        echo "An error occurred. dkms build error: ${RESULT}"
        exit $RESULT
    fi

    # Run dkms install
    dkms install -m ${DRV_NAME} -v ${DRV_VERSION} -k "${KVER}"
    RESULT=$?

    if [ "$RESULT" != "0" ]; then
        echo "An error occurred. dkms install error: ${RESULT}"
        exit $RESULT
    else
        echo "The driver was installed by dkms successfully."
    fi
fi

# Unblock wifi if rfkill is available
if command -v rfkill >/dev/null 2>&1; then
    rfkill unblock wlan
else
    echo "Unable to run $ rfkill unblock wlan"
fi

# Prompt for additional options
printf "Do you want to edit the driver options file now? (recommended) [Y/n] "
read -r yn
case "$yn" in
    [nN]) ;;
    *) ${TEXT_EDITOR} /etc/modprobe.d/${OPTIONS_FILE} ;;
esac

printf "Do you want to apply the new options by rebooting now? (recommended) [Y/n] "
read -r yn
case "$yn" in
    [nN]) ;;
    *) reboot ;;
esac
