CC=g++
#CC = gcc

LIB += ./lzma/7zFile.h ./lzma/7zTypes.h ./lzma/7zWindows.h ./lzma/Alloc.h ./lzma/Compiler.h ./lzma/CpuArch.h ./lzma/LzFind.h ./lzma/LzHash.h ./lzma/LzmaDec.h ./lzma/LzmaEnc.h ./lzma/LzmaUtil.h ./lzma/Precomp.h

LIB += BitmapTable.h bitsutil.h bloomfilter.h config.h fnv.h hashing.h timing.h

PROJECT_SRC += ./lzma/7zFile.c ./lzma/7zStream.c ./lzma/Alloc.c ./lzma/CpuArch.c ./lzma/LzFind.c ./lzma/LzmaDec.c ./lzma/LzmaEnc.c

PROJECT_SRC += bloomfilter.cpp fnv.c hashing.cpp main.cpp

CFLAGS += -std=c++11
#CFLAGS += -std=c99

#LDFLAGS += -lcrypto
LDFLAGS += -lm

NAME = bifm

all:bifm

bifm: ${LIB} ${PROJECT_SRC}
	${CC} $(CFLAGS) -o ${NAME} $(LIB) ${PROJECT_SRC} $(LDFLAGS)

clean:  
	rm -f bifm *.o



