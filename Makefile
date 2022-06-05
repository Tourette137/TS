compile:
	gcc -Wall auth.c `pkg-config fuse3 --cflags --libs` -g -o auth
	chmod u+s auth

	touch utils/passwd
	chmod 0600 utils/passwd

clean:
	rm -f auth
	rm -f utils/pipe_for_pins
	rm -f utils/passwd
	fusermount -u pastaTestes