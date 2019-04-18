
PLATFORM = linux
DTPSTLITE_LIBS=$(HOME)/gb28181_2016

CC      = gcc
CPP     = g++ -std=c++11
CXX     = g++
LD      = ld
AR      = ar

#CFLAGS += -std=c++11
CFLAGS += -I$(DTPSTLITE_LIBS)/src
CFLAGS += -I$(DTPSTLITE_LIBS)/include
LIBS += -leXosip2 -losip2 -losipparser2 -lpthread -liconv -ljson 

DIST=gb28181

all:${DIST}

Objs=gb28181.o algorithm.o osip_md5.o

${DIST}: ${Objs}
	${CXX}  $^ -o $@ ${LDFLAGS} $(LIBS)

#joy
-include *.d

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

.cpp.o:
	$(CPP) -c $(CXXFLAGS) $(CFLAGS) $< -o $@

clean:
	rm -f ${Objs}  ${DIST}


