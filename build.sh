#!/bin/sh

DIR=$1

sudo sh -c 'eval $(opam env --root=/opt/opam --set-root) && opam pin add vyos1x-config https://github.com/vyos/vyos1x-config.git#8835a91e8383319a6bb98de9fd400b4eb7883eb5 -y'

eval `opam config env`
make clean
make
