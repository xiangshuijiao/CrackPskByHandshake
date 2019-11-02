libjknbreak.so: main.o hmac_sha1.o fastpbkdf2.o wpa2break.o
	gcc --shared main.o hmac_sha1.o fastpbkdf2.o wpa2break.o -lcrypto  -o libjknbreak.so

# main: main.o hmac_sha1.o fastpbkdf2.o wpa2break.o
# 	gcc main.o hmac_sha1.o fastpbkdf2.o wpa2break.o -lcrypto -o crack


main.o: main.c
	gcc -c main.c -o main.o

hmac_sha1.o: hmac_sha1.c
	gcc -c hmac_sha1.c -o hmac_sha1.o

fastpbkdf2.o: fastpbkdf2.c
	gcc -c fastpbkdf2.c -std=c99 -o fastpbkdf2.o

wpa2break.o: wpa2break.c
	gcc -c wpa2break.c -o wpa2break.o
clean:
	rm *.o
