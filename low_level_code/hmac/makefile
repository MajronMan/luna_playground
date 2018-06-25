linux:
	gcc -c -Wall -Werror -fpic hmac.c
	gcc -shared hmac.o -L/usr/lib -lssl -o ../../native_libs/linux/libhmac_luna.so

macos:
	clang hmac.c \
		-L/usr/local/Cellar/openssl/1.0.2n/lib \
		-I/usr/local/Cellar/openssl/1.0.2n/include \
		-lssl -lcrypto \
		-shared -dynamiclib -fpic \
		-Wall -Werror \
		-o ../../native_libs/macos/libhmac_luna.dylib

example:
	gcc -L. -lhmac_luna -o test.out example.c
	export LD_LIBRARY_PATH=.
	./test.out
