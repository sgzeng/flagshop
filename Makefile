CFLAGS =-O0 -g -w -pthread -I/usr/local/ssl/include  -I../ -I/usr/local/lib  -I/usr/local/include
LD=-L /usr/lib  -lssl -lcrypto  -L /usr/local/lib/
CC = gcc
CLEANFILES = *.o

all: shop

shop:
	# ${CC} ${CFLAGS} -o ecdh ecdh.c $(LD)
	${CC} ${CFLAGS} -o server shop_server.c dictionary.c $(LD)
	${CC} ${CFLAGS} -o client shop_client.c $(LD)
	${CC} ${CFLAGS} -o wallet shop_wallet.c $(LD)
	${CC} ${CFLAGS} -o exp exp.c $(LD)
	${CC} ${CFLAGS} -o test test.c $(LD)

clean:
	rm -f ${CLEANFILES}
	rm -f ${PROGS}
	rm -f *~
