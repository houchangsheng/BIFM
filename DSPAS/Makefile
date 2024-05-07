CC=g++

LIB += 7zFile.h 7zTypes.h 7zWindows.h Alloc.h Compiler.h CpuArch.h LzFind.h LzHash.h LzmaDec.h LzmaEnc.h LzmaUtil.h Precomp.h

LIB += hashutil.h

PROJECT_SRC += 7zFile.c 7zStream.c Alloc.c CpuArch.c LzFind.c LzmaDec.c LzmaEnc.c

PROJECT_SRC += hashutil.cpp DCT.cpp

CFLAGS += -std=c++11

LDFLAGS +=-lcrypto

NAME = dspas

all: dspas

dspas: ${LIB} ${PROJECT_SRC}
	${CC} $(CFLAGS) -o ${NAME} $(LIB) ${PROJECT_SRC} $(LDFLAGS)

clean :  
	rm -f dspas *.o

