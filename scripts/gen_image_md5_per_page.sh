#!/bin/bash

SOURCE_DIR="$PWD/../"
IMAGE=${IMAGE:-"${SOURCE_DIR}/../out/Image"}
HEADER_PATH=${HEADER_PATH:-"${SOURCE_DIR}/include/common/"}

echo $IMAGE

FILE_SIZE=`stat --printf="%s\n" $IMAGE`

echo $FILE_SIZE

FILE_NUM_MAX=`expr $FILE_SIZE / 4096`

echo $FILE_NUM_MAX

REMAIN=`expr $FILE_SIZE - $FILE_NUM_MAX \* 4096`

echo $REMAIN

if [[ REMAIN -eq 0 ]]; then
    FILE_NUM_MAX=`expr FILE_NUM_MAX - 1`
fi

echo split image into $FILE_NUM_MAX + 1 pieces of 4K little files

echo "" > ${HEADER_PATH}/image_md5_data.h
echo "//this is generated file, don't touch by hand" >> ${HEADER_PATH}/image_md5_data.h
echo "__attribute__((section(\".rodata.md5\")))" >> ${HEADER_PATH}/image_md5_data.h
echo "unsigned long image_md5_per_page[][2]= {" >> ${HEADER_PATH}/image_md5_data.h

for (( i=0; i<=$FILE_NUM_MAX; i++ )) do
    #echo $i
    dd if=$IMAGE of=Image_page bs=4K skip=${i} count=1 &> /dev/null  
    MD5=`md5sum Image_page | cut -d ' ' -f 1`
    MD5_UPPER=${MD5:0:16}
    MD5_LOWER=${MD5:16:32}
    #echo $MD5 $MD5_UPPER $MD5_LOWER 
    v=$MD5_UPPER
    MD5_UPPER_BIG_ENDIAN=${v:14:2}${v:12:2}${v:10:2}${v:8:2}${v:6:2}${v:4:2}${v:2:2}${v:0:2}
    v=$MD5_LOWER
    MD5_LOWER_BIG_ENDIAN=${v:14:2}${v:12:2}${v:10:2}${v:8:2}${v:6:2}${v:4:2}${v:2:2}${v:0:2}
    echo -e -n "\t{ 0x${MD5_UPPER_BIG_ENDIAN}, " >> ${HEADER_PATH}/image_md5_data.h
    echo "0x${MD5_LOWER_BIG_ENDIAN} }," >> ${HEADER_PATH}/image_md5_data.h 
done

echo " }; " >> ${HEADER_PATH}/image_md5_data.h
