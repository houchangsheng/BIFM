CC=g++

LIB = config.h bitsutil.h fnv.h cuckoofilter.h hashutil.h printutil.h singletable.h timing.h
PROJECT_SRC = fnv.cpp hashutil.cpp main.cpp
CFLAGS += -std=c++11

LDFLAGS += -lm
LDFLAGS += -lcrypto

NAME = mrsh_cf

all:mrsh_cf

mrsh_cf: ${LIB} ${PROJECT_SRC}
	${CC} $(CFLAGS) -o ${NAME} $(LIB) ${PROJECT_SRC} $(LDFLAGS)

clean:  
	rm -f mrsh_cf *.o



