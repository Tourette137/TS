compile:
	gcc -Wall auth.c `pkg-config fuse3 --cflags --libs` -g -o auth
	chmod u+s auth

	touch utils/passwd
	chmod 0600 utils/passwd

	mkfifo utils/creds_fifo -m 0600 
clean:
	rm -f auth
	rm -f utils/creds_fifo
	rm -f utils/passwd
	fusermount -u pastaTestes