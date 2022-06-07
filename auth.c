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
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
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

int* authored = NULL;

char* cwd_path = NULL;
int cwd_path_size;

char* creds_fifo_path = NULL;
char* passwd_path = NULL;
char* python_script_path = NULL;
char* bash_pass_script_path = NULL;
char* bash_pin_script_path = NULL;

const char* CREDS_FIFO       = "/utils/creds_fifo";
const char* PASSWD_FILE      = "/utils/passwd";
const char* PYTHON_SCRIPT    = "/auth.py";
const char* BASH_PASS_SCRIPT = "/bash_pass.sh";
const char* BASH_PIN_SCRIPT  = "/bash_pin.sh";

void hash_password(char* buffer, char* password, char* salt)
{
    pid_t pid;
    int pipe_fd[2];

	// Creating pipe to send hashed password
	if (pipe(pipe_fd) == -1) {
		perror("Error on hash_password pipe");
		_exit(EXIT_FAILURE);
	}

	// Creating a child process
    if ((pid = fork()) == -1) {
		perror("Error on hash_password fork");
		_exit(EXIT_FAILURE);
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
		_exit(EXIT_FAILURE);
    }
    else {
        close(pipe_fd[1]);
        read(pipe_fd[0], buffer, HASHED_PASSWORD_BUFFER_SIZE);
        close(pipe_fd[0]);

		buffer[strcspn(buffer, "\r\n" )] = '\0';

		// Procedure to end child proccess
		int status;
		pid_t child_pid = wait(&status);

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) != EXIT_SUCCESS) {
				_exit(EXIT_FAILURE);
			}
		}
		else {
			fprintf(stderr, "Error in openssl child.\n");
			_exit(EXIT_FAILURE);
		}
    }
}

int auth_register()
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
		_exit(EXIT_FAILURE);
	}

	// Calculate password hash
    char *hashed_pass = (char*) malloc(HASHED_PASSWORD_BUFFER_SIZE * sizeof(char));
    hash_password(hashed_pass, password, NULL);

	// Get cellphone from stdin and append '+351' prefix
	char cellphone[11], cellphone_final[14];
	printf("\nEnter cellphone: (+351) ");
	fgets(cellphone, 11, stdin);
	cellphone[strcspn(cellphone, "\r\n" )] = '\0';

	sprintf(cellphone_final,"+351%s", cellphone);

	// Write user details do passwd file
	FILE* passwd_file = fopen(passwd_path, "a");

	if (passwd_file == NULL) {
		perror("Error opening passwd file");
		_exit(EXIT_FAILURE);
	}

	fprintf(passwd_file, "%s %s %s\n", username, cellphone_final, hashed_pass);

	fclose(passwd_file);
	free(hashed_pass);

	return 0;
}

void get_credentials(char* buffer_full_hashed_pass, char* buffer_pin)
{
	pid_t pid;
	int pass_pipe_fd[2];
	int pin_pipe_fd[2];

	// Creating pipe for the python script child to send hashed password
	if (pipe(pass_pipe_fd) == -1) { 
		perror("Error on python script child pipe");
		_exit(EXIT_FAILURE);
	}

	// Creating pipe for the python script child to send pin
	if (pipe(pin_pipe_fd) == -1) { 
		perror("Error on python script child pipe");
		_exit(EXIT_FAILURE);
	}

	// Creating the python script child process
	if ((pid = fork()) == -1) { 
		perror("Error on python script child fork");
		_exit(EXIT_FAILURE);
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
			_exit(EXIT_FAILURE);
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
/* PIN_DEBUG*/
				// Execute python script
				execl("/usr/bin/python3", "python3", python_script_path, cellphone, (char *) NULL);

				perror("Error executing python script");
				_exit(EXIT_FAILURE);
/**/
			}
		}
	
		// If username is not found in passwd file, an error is shown
		fprintf(stderr, "User not found in passwd file.\n");
		_exit(EXIT_FAILURE);
	}
	// Parent process that will get the pin and full hashed password from is child, through the pipes
	else {
		// Close pipes outputs
		close(pass_pipe_fd[1]);
		close(pin_pipe_fd[1]);

		// Reading full hashed pass from pipe
		read(pass_pipe_fd[0], buffer_full_hashed_pass, HASHED_PASSWORD_BUFFER_SIZE);
/* PIN_DEBUG*/
		// Reading pin from pipe
		read(pin_pipe_fd[0], buffer_pin, PIN_BUFFER_SIZE);
/**/
		// Close pipes inputs as they're no longer needed
		close(pass_pipe_fd[0]);
		close(pin_pipe_fd[0]);

		// Procedure to end child proccess
		int status;
		pid_t child_pid = wait(&status);

		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) != EXIT_SUCCESS) {
				_exit(EXIT_FAILURE);
			}
		}
		else {
			fprintf(stderr, "Error in python script child.\n");
			_exit(EXIT_FAILURE);
		}
	}
}

int validate_user_credentials(char* real_full_hashed_pass, int real_pin)
{
	pid_t pid, child_pid;
	int fd_fifo, status;

	// ---------------- PASSWORD VALIDATION ----------------
	char buffer_password[PASSWORD_BUFFER_SIZE];

	// Creating the password input terminal child process
	if ((pid = fork()) == -1) { 
		perror("Error on password input terminal child fork");
		_exit(EXIT_FAILURE);
	}

	// Child process that will run the bash password script and send user inputted password to his parent, through a FIFO
	if (pid == 0) {
		execl("/usr/bin/xterm", "xterm", "-e", "bash", bash_pass_script_path, creds_fifo_path, (char *) NULL);

		perror("Error executing bash password script");
		_exit(EXIT_FAILURE);
	}
	
	// Parent process that will get user inputted password from is child, through the FIFO
	
	// Read user inputted password from child output, written in the FIFO
	fd_fifo = open(creds_fifo_path, O_RDONLY);

	if (fd_fifo == -1) {
		perror("Error opening FIFO");
		_exit(EXIT_FAILURE);
	}

	// Reading password from FIFO
	while( read(fd_fifo, buffer_password, PASSWORD_BUFFER_SIZE) == 0 );
	buffer_password[strcspn(buffer_password, "\r\n" )] = '\0';

	close(fd_fifo);

	// Procedure to end child proccess
	child_pid = wait(&status);

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != EXIT_SUCCESS) {
			_exit(EXIT_FAILURE);
		}
	}
	else {
		fprintf(stderr, "Error in bash password script child.\n");
		_exit(EXIT_FAILURE);
	}

	char* inputted_password = (char*) malloc(sizeof(char) * (strlen(buffer_password) + 1));

	// Parsing inputted password from its buffer
	if(sscanf(buffer_password, "%s", inputted_password) != 1) {
		fprintf(stderr, "Error parsing password obtained from user input.\n");
		_exit(EXIT_FAILURE);
	}

	// Parse salt and password hash from the real full hashed pass
	strtok(real_full_hashed_pass, "$");
	char* salt = strtok(NULL, "$");
	char* password_hash = strtok(NULL, "$");

	// Calculate full hash of inputted password, given from the terminal
	char* inputted_password_hash = (char*) malloc(HASHED_PASSWORD_BUFFER_SIZE * sizeof(char));
	hash_password(inputted_password_hash, inputted_password, salt);

	// Parse inputted password hash, from the full hash
	strtok(inputted_password_hash, "$");
	strtok(NULL, "$");
	inputted_password_hash = strtok(NULL, "$");
	
	// Verify if inputted password hash matches with the real one
	if (strcmp(inputted_password_hash, password_hash) != 0){
		fprintf(stderr, "Error: Invalid password.\n");
		_exit(EXIT_FAILURE);
	}


	// ---------------- PIN VALIDATION ----------------
	char buffer_pin[PIN_BUFFER_SIZE];

	// Creating the pin input terminal child process
	if ((pid = fork()) == -1) { 
		perror("Error on pin input terminal child fork");
		_exit(EXIT_FAILURE);
	}

	// Child process that will run the bash pin script and send user inputted pin to his parent, through a FIFO
	if (pid == 0) {
		execl("/usr/bin/xterm", "xterm", "-e", "bash", bash_pin_script_path, creds_fifo_path, (char *) NULL);

		perror("Error executing bash pin script");
		_exit(EXIT_FAILURE);
	}

	// Parent process that will get user inputted pin from is child, through the FIFO

	// Read user inputted pin from child output, written in the FIFO
	fd_fifo = open(creds_fifo_path, O_RDONLY);

	if (fd_fifo == -1) {
		perror("Error opening FIFO");
		_exit(EXIT_FAILURE);
	}

	// Reading pin from FIFO
	while( read(fd_fifo, buffer_pin, PIN_BUFFER_SIZE) == 0 );
	buffer_pin[strcspn(buffer_pin, "\r\n" )] = '\0';

	close(fd_fifo);

	// Procedure to end child proccess
	child_pid = wait(&status);

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != EXIT_SUCCESS) {
			_exit(EXIT_FAILURE);
		}
	}
	else {
		fprintf(stderr, "Error in bash pin script child.\n");
		_exit(EXIT_FAILURE);
	}

	int inputted_pin;

	// Parsing inputted pin from its buffer
	if(sscanf(buffer_pin, "%d", &inputted_pin) != 1) {
		fprintf(stderr, "Error parsing pin obtained from user input.\n");
		_exit(EXIT_FAILURE);
	}

	// Verify if inputted pin matches with the real one
	if (inputted_pin != real_pin) {
		fprintf(stderr, "Error: Invalid PIN.\n");
		_exit(EXIT_FAILURE);
	}

	return 0;

}

int auth() {

	// Initialize buffers that will be used in the get_credential function
	char* buffer_full_hashed_pass = (char*) malloc(sizeof(char) * HASHED_PASSWORD_BUFFER_SIZE);
	char* buffer_pin = (char*) malloc(sizeof(char) * PIN_BUFFER_SIZE);

	// Fill buffers with the full hashed pass obtained from the passwd file and the pin obtained from the python script
	get_credentials(buffer_full_hashed_pass, buffer_pin);

	// Parse pin and full hashed pass from their buffers
	char* full_hashed_pass = (char*) malloc(sizeof(char) * (strlen(buffer_full_hashed_pass) + 1));
	int pin; //PIN_DEBUG

	// Parsing full hashed pass from its buffer
	if (sscanf(buffer_full_hashed_pass, "%s", full_hashed_pass) != 1) {
		fprintf(stderr, "Error parsing full hashed pass obtained from passwd file.\n");
		_exit(EXIT_FAILURE);
	}
	
	// Parsing pin from its buffer
	if(sscanf(buffer_pin, "%d", &pin) != 1) { 
		fprintf(stderr, "Error parsing pin obtained from python script.\n");
		_exit(EXIT_FAILURE);
	}

	// Freeing memory from the buffers as it no longer will be needed
	free(buffer_full_hashed_pass);
	free(buffer_pin);

	// Get user credentials inputted from the terminal and verify them
	int authorized = validate_user_credentials(full_hashed_pass, pin);

	return authorized;
}

int auth_timeout (int seconds) {

	pid_t pid;	// Process ID 

	// Creating a child process 
	if ((pid = fork()) == -1) { 

		//puts("Couldn't create child process to track the time."); 
		return 1; 

	}

	// Child process that will in 30 seconds update the authored flag
	if (pid == 0) {
		
		// Timeout
		sleep(seconds);
		
		*authored = -1;

		exit(0);	
	}
	
	return 0;
}

int auth_caller () {

	while (*authored  == 0); // Add sleep() for non active waiting

	if (*authored == -1) {

		*authored = 0;
		
		auth_timeout(30);  // TODO retirar isto
		// TODO muda prefixo das funcoes para nao ser igual ao eddy

		int access = auth();

		if (access == 0 && *authored == 0) *authored = 1;
		else *authored = -1;

		return access;

	} else if (*authored == 1) return 0;

	return auth_caller();

}

static void *auth_init(struct fuse_conn_info *conn,
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

static int auth_getattr(const char *path, struct stat *stbuf,
		struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_readlink(const char *path, char *buf, size_t size)
{
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int auth_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
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

static int auth_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	res = mknod_wrapper(AT_FDCWD, path, NULL, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_rename(const char *from, const char *to, unsigned int flags)
{
	int res;

	if (flags)
		return -EINVAL;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_chmod(const char *path, mode_t mode,
		struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_chown(const char *path, uid_t uid, gid_t gid,
		struct fuse_file_info *fi)
{
	(void) fi;
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_truncate(const char *path, off_t size,
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
static int auth_utimens(const char *path, const struct timespec ts[2],
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

static int auth_create(const char *path, mode_t mode,
		struct fuse_file_info *fi)
{
	int res;

	res = open(path, fi->flags, mode);
	if (res == -1)
		return -errno;

	fi->fh = res;
	return 0;
}

static int auth_open(const char *path, struct fuse_file_info *fi)
{

	int ret = auth_caller();

	if (*authored != 1)
		return ret;

	int res;

	res = open(path, fi->flags);
	if (res == -1) return -errno;

	fi->fh = res;
	return 0;
	
}

static int auth_read(const char *path, char *buf, size_t size, off_t offset,
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

static int auth_write(const char *path, const char *buf, size_t size,
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

static int auth_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int auth_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;
	close(fi->fh);
	return 0;
}

static int auth_fsync(const char *path, int isdatasync,
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
static int auth_fallocate(const char *path, int mode,
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
static int auth_setxattr(const char *path, const char *name, const char *value,
		size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int auth_getxattr(const char *path, const char *name, char *value,
		size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int auth_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int auth_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

#ifdef HAVE_COPY_FILE_RANGE
static ssize_t auth_copy_file_range(const char *path_in,
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

static off_t auth_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
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

static struct fuse_operations auth_oper = {
	.init       = auth_init,
	.getattr	= auth_getattr,
	.access		= auth_access,
	.readlink	= auth_readlink,
	.readdir	= auth_readdir,
	.mknod		= auth_mknod,
	.mkdir		= auth_mkdir,
	.symlink	= auth_symlink,
	.unlink		= auth_unlink,
	.rmdir		= auth_rmdir,
	.rename		= auth_rename,
	.link		= auth_link,
	.chmod		= auth_chmod,
	.chown		= auth_chown,
	.truncate	= auth_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= auth_utimens,
#endif
	.open		= auth_open,
	.create 	= auth_create,
	.read		= auth_read,
	.write		= auth_write,
	.statfs		= auth_statfs,
	.release	= auth_release,
	.fsync		= auth_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= auth_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= auth_setxattr,
	.getxattr	= auth_getxattr,
	.listxattr	= auth_listxattr,
	.removexattr	= auth_removexattr,
#endif
#ifdef HAVE_COPY_FILE_RANGE
	.copy_file_range = auth_copy_file_range,
#endif
	.lseek = auth_lseek,
};


void initializePaths() {
	
	char cwd_buffer[FILENAME_MAX];
  	getcwd(cwd_buffer, FILENAME_MAX );

	cwd_path_size = strlen(cwd_buffer);

	cwd_path = (char*) malloc(cwd_path_size * sizeof(char));
	strcpy(cwd_path, cwd_buffer);

	creds_fifo_path = (char*) malloc((cwd_path_size + strlen(CREDS_FIFO)) * sizeof(char));
	sprintf(creds_fifo_path, "%s%s", cwd_buffer, CREDS_FIFO);

	passwd_path = (char*) malloc((cwd_path_size + strlen(PASSWD_FILE)) * sizeof(char));
	sprintf(passwd_path, "%s%s", cwd_buffer, PASSWD_FILE);

	python_script_path = (char*) malloc((cwd_path_size + strlen(PYTHON_SCRIPT)) * sizeof(char));
	sprintf(python_script_path, "%s%s", cwd_buffer, PYTHON_SCRIPT);

	bash_pass_script_path = (char*) malloc((cwd_path_size + strlen(BASH_PASS_SCRIPT)) * sizeof(char));
	sprintf(bash_pass_script_path, "%s%s", cwd_buffer, BASH_PASS_SCRIPT);

	bash_pin_script_path = (char*) malloc((cwd_path_size + strlen(BASH_PIN_SCRIPT)) * sizeof(char));
	sprintf(bash_pin_script_path, "%s%s", cwd_buffer, BASH_PIN_SCRIPT);
}

int main(int argc, char *argv[])
{
	initializePaths();

	if (argc > 1 && strcmp(argv[1],"register") == 0 ) {
		
		return auth_register();

	}

	else {

		authored = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		*authored = -1;

		return fuse_main(argc, argv, &auth_oper, NULL);
	}

}

/* TODO:
Ideias para implementar:
- Mudar o nome das funções auth para outro e comnetários
- Acrescentar por exemplo "./auth registar" para registar novos Users e acrescentar ao usermap
- Possuir uma estrutura de dados que sempre que um Utilizador se regista dá update nela mesma com um SIGALARM por exemplo;
- guardar hash da password
- verificar tamanho do número de telemóvel inserido
- asteriscos quando se escreve password

usermap:
criar user (tourette, pass, nrTelemovel)
1 - load para a estrutura

Descobrir como mudar pin para ser sempre o mesmo

Descobrir o que é mmap
*/		