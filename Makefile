compile:
	gcc -Wall our_passthrough.c `pkg-config fuse3 --cflags --libs` -g -o our_passthrough
	chmod u+s our_passthrough

	touch utils/passwd
	chmod 0600 utils/passwd
	chmod +t utils/passwd

	mkfifo utils/creds_fifo -m 0600 
	chmod +t utils/creds_fifo

clean:
	rm -f our_passthrough
	rm -f utils/creds_fifo
	rm -f utils/passwd
	fusermount -u pastaTestes