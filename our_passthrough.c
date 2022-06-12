/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>
  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * This file system mirrors the existing file system hierarchy of the
 * system, starting at the root file system. This is implemented by
 * just "passing through" all requests to the corresponding user-space
 * libc functions. Its performance is terrible.
 *
 * Compile with
 *
 *     gcc -Wall our_passthrough.c `pkg-config fuse3 --cflags --libs` -o our_passthrough
 *
 * ## Source code ##
 * \include our_passthrough.c
 */


#define FUSE_USE_VERSION 31

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#ifdef __FreeBSD__
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "passthrough_helpers.h"
	
#define USERNAME_BUFFER_SIZE 34
#define PASSWORD_BUFFER_SIZE 128
#define HASHED_PASSWORD_BUFFER_SIZE 64
#define PIN_BUFFER_SIZE 8
#define PASSWD_FILE_LINE_BUFFER_SIZE 256

enum AUTH_STATUS {
	AUTH_UNAUTHORIZED = -1,
	AUTH_IN_PROCESS   = 0,
	AUTH_AUTHORIZED   = 1,
};

int* authorized = NULL;

char* cwd_path = NULL;
int cwd_path_size;

char* creds_fifo_path = NULL;
char* passwd_path = NULL;
char* python_script_path = NULL;
char* bash_pass_script_path = NULL;
char* bash_pin_script_path = NULL;

const char* CREDS_FIFO       = "/utils/creds_fifo";
const char* PASSWD_FILE      = "/utils/passwd";
const char* PYTHON_SCRIPT    = "/python_pin.py";
const char* BASH_PASS_SCRIPT = "/bash_pass.sh";
const char* BASH_PIN_SCRIPT  = "/bash_pin.sh";

int hash_password(char* buffer, char* password, char* salt)
{
    pid_t pid;
    int pipe_fd[2];

	// Creating pipe to send hashed password
	if (pipe(pipe_fd) == -1) {
		perror("Error on hash_password pipe");
		return -EACCES;
	}

	// Creating a child process
    if ((pid = fork()) == -1) {
		perror("Error on hash_password fork");
		return -EACCES;
    }

    // Child process that will run openssl
    if (pid == 0) {
        close(pipe_fd[0]);
        dup2(pipe_fd[1], 1);
		close(pipe_fd[1]);


		if (salt == NULL)
        	execl("/usr/bin/openssl", "openssl", "passwd", "-5", password, NULL);
		else
			execl("/usr/bin/openssl", "openssl", "passwd", "-5", "-salt", salt, password, NULL);

		perror("Error executing openssl");
		return -EACCES;
    }
    else {
        close(pipe_fd[1]);
        read(pipe_fd[0], buffer, HASHED_PASSWORD_BUFFER_SIZE);
        close(pipe_fd[0]);

		buffer[strcspn(buffer, "\r\n" )] = '\0';

		// Procedure to end child proccess
		int status;
		//pid_t child_pid = wait(&status);
		wait(&status);

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) != EXIT_SUCCESS) {
				return -EACCES;
			}
		}
		else {
			fprintf(stderr, "Error in openssl child.\n");
			return -EACCES;
		}

		return 0;
    }
}

int user_register()
{
	// Get username 
	char username[USERNAME_BUFFER_SIZE];
	getlogin_r(username, sizeof(username));
	printf("Username: %s\n", username);

	// Get password from stdin
	char password[PASSWORD_BUFFER_SIZE];  // TODO não aparecer password no ecrã
	char password_again[PASSWORD_BUFFER_SIZE];
	printf("\nEnter password: ");
	fgets(password, PASSWORD_BUFFER_SIZE, stdin);
    password[strcspn(password, "\r\n" )] = '\0';

	printf("Enter password again: ");
	fgets(password_again, PASSWORD_BUFFER_SIZE, stdin);
    password_again[strcspn(password_again, "\r\n" )] = '\0';

	if (strcmp(password, password_again) != 0) {
		fprintf(stderr, "Passwords are not the same.\n");
		return -EACCES;
	}

	// Calculate password hash
    char *hashed_pass = (char*) malloc(HASHED_PASSWORD_BUFFER_SIZE * sizeof(char));
    if (hash_password(hashed_pass, password, NULL) != 0 ) {
		return -EACCES;
	}

	// Get cellphone from stdin and append '+351' prefix
	char cellphone[10], cellphone_final[14];
	printf("\nEnter cellphone: (+351) ");
	fgets(cellphone, 10, stdin);
	if (strlen(cellphone) > 9) {
		fprintf(stderr, "Cellphone number too big.\n");
		return -EACCES;
	}
	cellphone[strcspn(cellphone, "\r\n" )] = '\0';

	sprintf(cellphone_final,"+351%s", cellphone);

	// Write user details do passwd file
	FILE* passwd_file = fopen(passwd_path, "a");

	if (passwd_file == NULL) {
		perror("Error opening passwd file");
		return -EACCES;
	}

	fprintf(passwd_file, "%s %s %s\n", username, cellphone_final, hashed_pass);

	fclose(passwd_file);
	free(hashed_pass);

	return 0;
}

int get_credentials(char* buffer_full_hashed_pass, char* buffer_pin)
{
	pid_t pid;
	int pass_pipe_fd[2];
	int pin_pipe_fd[2];

	// Creating pipe for the python script child to send hashed password
	if (pipe(pass_pipe_fd) == -1) { 
		perror("Error on python script child pipe");
		return -EACCES;
	}

	// Creating pipe for the python script child to send pin
	if (pipe(pin_pipe_fd) == -1) { 
		perror("Error on python script child pipe");
		return -EACCES;
	}

	// Creating the python script child process
	if ((pid = fork()) == -1) { 
		perror("Error on python script child fork");
		return -EACCES;
	}

	// Child process that will run the python script and send pin and full hashed password to his parent, through the pipes created
	if (pid == 0) {

		// Close pipes inputs
		close(pass_pipe_fd[0]);
		close(pin_pipe_fd[0]);

		// Setting pin pipe as stdout so python script writes to it
		dup2(pin_pipe_fd[1], 1);
		close(pin_pipe_fd[1]);

		FILE* passwd_file = fopen(passwd_path, "r");

		if (passwd_file == NULL) {
			perror("Error opening passwd file");
			return -EACCES;
		}

		char username[USERNAME_BUFFER_SIZE];
		getlogin_r(username, sizeof(username));

		char line[PASSWD_FILE_LINE_BUFFER_SIZE];
		while( fgets(line, PASSWD_FILE_LINE_BUFFER_SIZE, passwd_file) != NULL) {

			line[strcspn(line, "\r\n" )] = '\0';
	
			// Get username from line
			char* token = strtok(line," ");
	
			if (strcmp(token, username) == 0) {

				// Close passwd file as it's no longer needed
				fclose(passwd_file);
			
				// Get cellphone from line
				token = strtok(NULL," ");
				char* cellphone = token;

				// Get full hashed password from line
				token = strtok(NULL," ");
				char* full_hashed_pass = token;
				write(pass_pipe_fd[1], full_hashed_pass, strlen(full_hashed_pass));
				close(pass_pipe_fd[1]);

				// Execute python script
				execl("/usr/bin/python3", "python3", python_script_path, cellphone, (char *) NULL);

				perror("Error executing python script");
				return -EACCES;

			}
		}
	
		// If username is not found in passwd file, an error is shown
		fprintf(stderr, "User not found in passwd file.\n");
		return -EACCES;
	}
	// Parent process that will get the pin and full hashed password from is child, through the pipes
	else {
		// Procedure to end child proccess
		int status;
		//pid_t child_pid = wait(&status);
		wait(&status);

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) != EXIT_SUCCESS) {
				return -EACCES;
			}
		}
		else {
			fprintf(stderr, "Error in python script child.\n");
			return -EACCES;
		}

		// Close pipes outputs
		close(pass_pipe_fd[1]);
		close(pin_pipe_fd[1]);

		// Reading full hashed pass from pipe
		read(pass_pipe_fd[0], buffer_full_hashed_pass, HASHED_PASSWORD_BUFFER_SIZE);

		// Reading pin from pipe
		read(pin_pipe_fd[0], buffer_pin, PIN_BUFFER_SIZE);
        buffer_pin[strcspn ( buffer_pin, "\n" )] = '\0';

		// Close pipes inputs as they're no longer needed
		close(pass_pipe_fd[0]);
		close(pin_pipe_fd[0]);

		return 0;
	}
}

int validate_user_credentials(char* real_full_hashed_pass, int real_pin)
{
	pid_t pid;
	int fd_fifo, status;

	// ---------------- PASSWORD VALIDATION ----------------
	char buffer_password[PASSWORD_BUFFER_SIZE];

	// Creating the password input terminal child process
	if ((pid = fork()) == -1) { 
		perror("Error on password input terminal child fork");
		return -EACCES;
	}

	// Child process that will run the bash password script and send user inputted password to his parent, through a FIFO
	if (pid == 0) {
		execl("/usr/bin/xterm", "xterm", "-e", "bash", bash_pass_script_path, creds_fifo_path, (char *) NULL);

		perror("Error executing bash password script");
		return -EACCES;
	}
	
	// Parent process that will get user inputted password from is child, through the FIFO
	
	// Read user inputted password from child output, written in the FIFO
	fd_fifo = open(creds_fifo_path, O_RDONLY);

	if (fd_fifo == -1) {
		perror("Error opening FIFO");
		return -EACCES;
	}

	// Procedure to end child proccess
	//child_pid = wait(&status);
	wait(&status);

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != EXIT_SUCCESS) {
			return -EACCES;
		}
	}
	else {
		fprintf(stderr, "Error in bash pin script child.\n");
		return -EACCES;
	}

	// Reading password from FIFO
	while( read(fd_fifo, buffer_password, PASSWORD_BUFFER_SIZE) == 0 );
	buffer_password[strcspn(buffer_password, "\r\n" )] = '\0';

	close(fd_fifo);

	char* inputted_password = (char*) malloc(sizeof(char) * (strlen(buffer_password) + 1));

	// Parsing inputted password from its buffer
	if(sscanf(buffer_password, "%s", inputted_password) != 1) {
		fprintf(stderr, "Error parsing password obtained from user input.\n");
		return -EACCES;
	}

	// Parse salt and password hash from the real full hashed pass
	strtok(real_full_hashed_pass, "$");
	char* salt = strtok(NULL, "$");
	char* password_hash = strtok(NULL, "$");

	// Calculate full hash of inputted password, given from the terminal
	char* inputted_password_hash = (char*) malloc(HASHED_PASSWORD_BUFFER_SIZE * sizeof(char));
	if (hash_password(inputted_password_hash, inputted_password, salt) != 0) {
		return -EACCES;
	}

	// Parse inputted password hash, from the full hash
	strtok(inputted_password_hash, "$");
	strtok(NULL, "$");
	inputted_password_hash = strtok(NULL, "$");
	
	// Verify if inputted password hash matches with the real one
	if (strcmp(inputted_password_hash, password_hash) != 0){
		fprintf(stderr, "Error: Invalid password.\n");
		return -EACCES;
	}


	// ---------------- PIN VALIDATION ----------------
	char buffer_pin[PIN_BUFFER_SIZE];

	// Creating the pin input terminal child process
	if ((pid = fork()) == -1) { 
		perror("Error on pin input terminal child fork");
		return -EACCES;
	}

	// Child process that will run the bash pin script and send user inputted pin to his parent, through a FIFO
	if (pid == 0) {
		execl("/usr/bin/xterm", "xterm", "-e", "bash", bash_pin_script_path, creds_fifo_path, (char *) NULL);

		perror("Error executing bash pin script");
		return -EACCES;
	}

	// Parent process that will get user inputted pin from is child, through the FIFO

	// Read user inputted pin from child output, written in the FIFO
	fd_fifo = open(creds_fifo_path, O_RDONLY);

	if (fd_fifo == -1) {
		perror("Error opening FIFO");
		return -EACCES;
	}

	// Procedure to end child proccess
	//child_pid = wait(&status);
	wait(&status);

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != EXIT_SUCCESS) {
			return -EACCES;
		}
	}
	else {
		fprintf(stderr, "Error in bash pin script child.\n");
		return -EACCES;
	}

	// Reading pin from FIFO
	while( read(fd_fifo, buffer_pin, PIN_BUFFER_SIZE) == 0 );
	buffer_pin[strcspn(buffer_pin, "\r\n" )] = '\0';

	close(fd_fifo);

	int inputted_pin;

	// Parsing inputted pin from its buffer
	if(sscanf(buffer_pin, "%d", &inputted_pin) != 1) {
		fprintf(stderr, "Error parsing pin obtained from user input.\n");
		return -EACCES;
	}

	// Verify if inputted pin matches with the real one
	if (inputted_pin != real_pin) {
		fprintf(stderr, "Error: Invalid PIN.\n");
		return -EACCES;
	}

	return 0;

}

int authenticate_user()
{
	// Initialize buffers that will be used in the get_credential function
	char* buffer_full_hashed_pass = (char*) malloc(sizeof(char) * HASHED_PASSWORD_BUFFER_SIZE);
	char* buffer_pin = (char*) malloc(sizeof(char) * PIN_BUFFER_SIZE);

	// Fill buffers with the full hashed pass obtained from the passwd file and the pin obtained from the python script
	if (get_credentials(buffer_full_hashed_pass, buffer_pin) != 0) {
		return -EACCES;
	}

	// Parse pin and full hashed pass from their buffers
	char* full_hashed_pass = (char*) malloc(sizeof(char) * (strlen(buffer_full_hashed_pass) + 1));
	int pin; //PIN_DEBUG

	// Parsing full hashed pass from its buffer
	if (sscanf(buffer_full_hashed_pass, "%s", full_hashed_pass) != 1) {
		fprintf(stderr, "Error parsing full hashed pass obtained from passwd file.\n");
		return -EACCES;
	}
	
	// Parsing pin from its buffer
	if(sscanf(buffer_pin, "%d", &pin) != 1) { 
		fprintf(stderr, "Error parsing pin obtained from python script.\n");
		return -EACCES;
	}

	// Freeing memory from the buffers as it no longer will be needed
	free(buffer_full_hashed_pass);
	free(buffer_pin);

	// Get user credentials inputted from the terminal and verify them
	int authorized = validate_user_credentials(full_hashed_pass, pin);

	return authorized;
}

int authentication_caller()
{
	while (*authorized == AUTH_IN_PROCESS);

	if (*authorized == AUTH_UNAUTHORIZED) {

		*authorized = AUTH_IN_PROCESS;

		int res = authenticate_user();

		if (res == 0 && *authorized == AUTH_IN_PROCESS)
			*authorized = AUTH_AUTHORIZED;
		else
			*authorized = AUTH_UNAUTHORIZED;

		return res;

	}

	else {
		return authentication_caller();
	}
}

static void *xmp_init(struct fuse_conn_info *conn,
			  struct fuse_config *cfg)
{
	(void) conn;
	cfg->use_ino = 1;

	/* Pick up changes from lower filesystem right away. This is
	   also necessary for better hardlink support. When the kernel
	   calls the unlink() handler, it does not know the inode of
	   the to-be-removed entry and can therefore not invalidate
	   the cache of the associated inode - resulting in an
	   incorrect st_nlink value being reported for any remaining
	   hardlinks to this inode. */
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;

	return NULL;
}

static int xmp_getattr(const char *path, struct stat *stbuf,
			   struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			   off_t offset, struct fuse_file_info *fi,
			   enum fuse_readdir_flags flags)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	(void) flags;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	res = mknod_wrapper(AT_FDCWD, path, NULL, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to, unsigned int flags)
{
	int res;

	if (flags)
		return -EINVAL;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode,
			 struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid,
			 struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size,
			struct fuse_file_info *fi)
{
	int res;

	if (fi != NULL)
		res = ftruncate(fi->fh, size);
	else
		res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2],
		struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

static int xmp_create(const char *path, mode_t mode,
			  struct fuse_file_info *fi)
{
	int res;

	res = open(path, fi->flags, mode);
	if (res == -1)
		return -errno;

	fi->fh = res;
	return 0;
}

static int our_open(const char *path, struct fuse_file_info *fi)
{
	authentication_caller();

	if (*authorized != AUTH_AUTHORIZED) {
		*authorized = AUTH_UNAUTHORIZED;
		return -EACCES;
	}

	*authorized = AUTH_UNAUTHORIZED;
	
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	fi->fh = res;
	return 0;	
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
			struct fuse_file_info *fi)
{
	int fd;
	int res;

	if(fi == NULL)
		fd = open(path, O_RDONLY);
	else
		fd = fi->fh;

	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	if(fi == NULL)
		close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
			 off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	if(fi == NULL)
		fd = open(path, O_WRONLY);
	else
		fd = fi->fh;

	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	if(fi == NULL)
		close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	close(fi->fh);
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
			 struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;

	if (mode)
		return -EOPNOTSUPP;

	if(fi == NULL)
		fd = open(path, O_WRONLY);
	else
		fd = fi->fh;

	if (fd == -1)
		return -errno;

	res = -posix_fallocate(fd, offset, length);

	if(fi == NULL)
		close(fd);
	return res;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

#ifdef HAVE_COPY_FILE_RANGE
static ssize_t xmp_copy_file_range(const char *path_in,
				   struct fuse_file_info *fi_in,
				   off_t offset_in, const char *path_out,
				   struct fuse_file_info *fi_out,
				   off_t offset_out, size_t len, int flags)
{
	int fd_in, fd_out;
	ssize_t res;

	if(fi_in == NULL)
		fd_in = open(path_in, O_RDONLY);
	else
		fd_in = fi_in->fh;

	if (fd_in == -1)
		return -errno;

	if(fi_out == NULL)
		fd_out = open(path_out, O_WRONLY);
	else
		fd_out = fi_out->fh;

	if (fd_out == -1) {
		close(fd_in);
		return -errno;
	}

	res = copy_file_range(fd_in, &offset_in, fd_out, &offset_out, len,
			flags);
	if (res == -1)
		res = -errno;

	close(fd_out);
	close(fd_in);

	return res;
}
#endif

static off_t xmp_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
{
	int fd;
	off_t res;

	if (fi == NULL)
		fd = open(path, O_RDONLY);
	else
		fd = fi->fh;

	if (fd == -1)
		return -errno;

	res = lseek(fd, off, whence);
	if (res == -1)
		res = -errno;

	if (fi == NULL)
		close(fd);
	return res;
}

static const struct fuse_operations xmp_oper = {
	.init       = xmp_init,
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= xmp_utimens,
#endif
	.open		= our_open,
	.create 	= xmp_create,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
#ifdef HAVE_COPY_FILE_RANGE
	.copy_file_range = xmp_copy_file_range,
#endif
	.lseek      = xmp_lseek,
};


void initializePaths() {
	
	char cwd_buffer[FILENAME_MAX];
  	getcwd(cwd_buffer, FILENAME_MAX );

	cwd_path_size = strlen(cwd_buffer);

	cwd_path = (char*) malloc(cwd_path_size * sizeof(char));
	strcpy(cwd_path, cwd_buffer);

	creds_fifo_path = (char*) malloc((cwd_path_size + strlen(CREDS_FIFO) + 1) * sizeof(char));
	sprintf(creds_fifo_path, "%s%s", cwd_buffer, CREDS_FIFO);

	passwd_path = (char*) malloc((cwd_path_size + strlen(PASSWD_FILE) + 1) * sizeof(char));
	sprintf(passwd_path, "%s%s", cwd_buffer, PASSWD_FILE);

	python_script_path = (char*) malloc((cwd_path_size + strlen(PYTHON_SCRIPT) + 1) * sizeof(char));
	sprintf(python_script_path, "%s%s", cwd_buffer, PYTHON_SCRIPT);

	bash_pass_script_path = (char*) malloc((cwd_path_size + strlen(BASH_PASS_SCRIPT) + 1) * sizeof(char));
	sprintf(bash_pass_script_path, "%s%s", cwd_buffer, BASH_PASS_SCRIPT);

	bash_pin_script_path = (char*) malloc((cwd_path_size + strlen(BASH_PIN_SCRIPT) + 1) * sizeof(char));
	sprintf(bash_pin_script_path, "%s%s", cwd_buffer, BASH_PIN_SCRIPT);
}

int main(int argc, char *argv[])
{
	initializePaths();

	if (argc > 1 && strcmp(argv[1],"register") == 0 ) {
		
		return user_register();

	}

	else {

		authorized = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		*authorized = AUTH_UNAUTHORIZED;

		return fuse_main(argc, argv, &xmp_oper, NULL);
	}

}
	