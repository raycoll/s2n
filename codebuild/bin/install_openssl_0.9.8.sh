#!/bin/bash

set -eu

usage() {
    echo "install_openssl_1_0_2.sh build_dir install_dir os_name"
    exit 1
}

if [ "$#" -ne "3" ]; then
    usage
fi

BUILD_DIR=$1
INSTALL_DIR=$2
OS_NAME=$3



cd "$BUILD_DIR"
wget https://www.openssl.org/source/old/0.9.x/openssl-0.9.8zh.tar.gz
tar xzvf openssl-0.9.8zh.tar.gz
cd openssl-0.9.8zh

if [ "$OS_NAME" == "linux" ]; then
    CONFIGURE="./config -d"
elif [ "$OS_NAME" == "osx" ]; then
    CONFIGURE="./Configure darwin64-x86_64-cc"
else
    echo "Invalid platform! $OS_NAME"
    usage
fi

mkdir -p $INSTALL_PREFIX
$CONFIGURE --prefix=$INSTALL_PREFIX
make depend
make -j8
make install

