CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -Wshadow
run_test_vectors:
	$(CC) $(CFLAGS) -o run_test_vectors encrypt.c test_vectors.c
.PHONY : clean
clean :
		-rm run_test_vectors