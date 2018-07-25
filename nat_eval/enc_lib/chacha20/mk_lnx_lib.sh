#!/bin/bash

yasm="../lib/yasm/yasm"

pushd .
rm *.o *.a
$yasm -D__linux__ -g dwarf2 -f elf64 chacha.s -o chacha.o
ar cru libchacha.a chacha.o
popd
