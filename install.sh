#!/bin/bash

if [ $UID -ne 0 ]; then
    echo "This script must be run as root!"
    echo "Example:  sudo $0"
    echo "      or  sudo PREFIX=/usr/local $0"
    exit 1
fi

PREFIX=${PREFIX:-/usr}
bindir=${PREFIX}/bin

echo "Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

echo "Installing tools..."
install -Dm 0755 eblih.py ${bindir}/eblih > /dev/null 2>&1
install -Dm 0755 bliny.sh ${bindir}/bliny > /dev/null 2>&1

echo "Installation successful!"
echo "Now type:"
echo "  bliny bootstrap # Only if you haven't yet a SSH key."
