all: pam_resolve.so

pam_resolve.o: pam_resolve.c
	gcc -Wall -fPIC -c pam_resolve.c

pam_resolve.so: pam_resolve.o
	gcc -shared -o pam_resolve.so pam_resolve.o -lpam

clean:
	rm *.so *.o
