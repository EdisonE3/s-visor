#!/bin/bash

SOURCE_DIR="$PWD/../"

rm ${SOURCE_DIR}/include/virt/asm-offsets.h
echo "#pragma once\n" >> ${SOURCE_DIR}/include/virt/asm-offsets.h
echo "/*This file is generated. Please do not modify it!*/\n" >> ${SOURCE_DIR}/include/virt/asm-offsets.h
sed -f ${SOURCE_DIR}/scripts/asm-offsets.sed < ${SOURCE_DIR}/include/virt/asm-offsets.s >> ${SOURCE_DIR}/include/virt/asm-offsets.h
rm ${SOURCE_DIR}/include/virt/asm-offsets.s
