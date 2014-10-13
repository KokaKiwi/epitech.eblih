#!/bin/bash

if [ $UID -ne 0 ]; then
    echo "This script must be run as root!"
    echo "Example:  sudo $0"
    echo "      or  sudo PREFIX=/usr/local $0"
    exit 1
fi

PREFIX=${PREFIX:-/usr}
bindir=${PREFIX}/bin

LOGFILE="install.log"

log() {
    echo $* | tee -a ${LOGFILE}
}

echo >>install.log

log "Installing dependencies..."
easy_install pip >>install.log 2>&1
pip install -r requirements.txt >>install.log 2>&1

log "Installing tools..."
install -Dm 0755 eblih.py ${bindir}/eblih >>install.log 2>&1
install -Dm 0755 bliny.sh ${bindir}/bliny >>install.log 2>&1

log "Installation successful!"
echo "Now type:"
echo "  bliny bootstrap # Only if you haven't yet a SSH key."
