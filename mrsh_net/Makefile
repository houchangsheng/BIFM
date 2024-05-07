CC=g++
#CC = gcc

LIB = timing.h config.h bloomfilter.h fnv.h hashing.h
PROJECT_SRC = bloomfilter.cpp fnv.c hashing.c main.cpp
CFLAGS += -std=c++11
#CFLAGS += -std=c99

#LDFLAGS += -lcrypto
LDFLAGS += -lm

NAME = mrsh_net

all:mrsh_net

mrsh_net: ${LIB} ${PROJECT_SRC}
	${CC} $(CFLAGS) -o ${NAME} $(LIB) ${PROJECT_SRC} $(LDFLAGS)

clean:  
	rm -f mrsh_net *.o



