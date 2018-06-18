hmac:
	gcc -c -Wall -Werror -fpic hmac.c
	gcc -shared hmac.o -L/usr/lib -lssl -o libhmac_luna.so

example:
	gcc -L. -lhmac_luna -o test.out example.c
	export LD_LIBRARY_PATH=.
	./test.out
