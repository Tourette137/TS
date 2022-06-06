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

int* authored = NULL;

char* cwd_path = NULL;
int cwd_path_size;

char* pin_pipe_path = NULL;
char* passwd_path = NULL;


const char* PIN_PIPE    = "/utils/pipe_for_pins";
const char* PASSWD_FILE = "/utils/passwd";



int auth_register() {

	//TODO: criar estrutura (se tiver não acrescentar) 

	setuid(0);
	FILE* passwdFile = fopen(passwd_path, "a");

	char username[100];
	getlogin_r(username, sizeof(username));

	printf("\nUsername: %s\n\n", username);

	char password[100];
	printf("Enter password: ");
	fgets(password, 100, stdin);

	printf("Entered password: %s\n", password);

	char telemovelFinal[14];
	char telemovel[10];
	printf("Enter telemovel: (+351)");
	fgets(telemovel, 10, stdin);

	sprintf(telemovelFinal,"+351%s", telemovel);
	printf("Entered telemovel: %s\n", telemovelFinal);

	fprintf(passwdFile, "%s %s %s", username, telemovelFinal, password);

	fclose(passwdFile);

	return 0;
}


int auth() {

	pid_t pid;			// Process ID 
	int channelPass[2];		// Pipe to grab the output
	int channelPin[2];		// Pipe to grab the output

	// Creating a pipe
	if (pipe(channelPass) == -1) { 
		
		//puts("Couldn't create pipe."); 
		return 1; 

	}

	// Creating a pipe
	if (pipe(channelPin) == -1) { 
		
		//puts("Couldn't create pipe."); 
		return 1; 

	}

	// Creating a child process
	if ((pid = fork()) == -1) { 

		//puts("Couldn't create child process."); 
		return 2; 

	}

	// Child process that will execute the python program
	if (pid == 0) {

		close(channelPass[0]);
		close(channelPin[0]);

		dup2(channelPin[1], 1);

		setuid(0);
		FILE* passwdFile = fopen(passwd_path, "r");

		if (passwdFile != NULL) {

			char username[100];
			getlogin_r(username, sizeof(username));

			char line[100];
			while( fgets(line, 100, passwdFile) != NULL) {
		
				char* token;
				token = strtok(line," ");
		
				if (strcmp(token, username) == 0) {
				
					token = strtok(NULL," ");
					char* cellphone = token;

					token = strtok(NULL," ");
					char* password = token;
					write(channelPass[1], password, sizeof(password));

					// Executing program to pip
					char pythonFile[cwd_path_size + 9];
					sprintf(pythonFile, "%s/auth.py", cwd_path);

					execl("/usr/bin/python3", "python3", pythonFile, cellphone, (char *) NULL);

					break;

				}
			}

			close(channelPass[1]);
			close(channelPin[1]);

			//puts("User not in the user map.");
			return 7;

		} else {
		
			//puts("Couldn't open user map");
			return 8;
		
		}

		//puts("10001");

	// Parent process that will grab the output from the child
	} else {

		close(channelPass[1]);
		close(channelPin[1]);

		// Buffer Password
		char buffer_pass[1024];	
		// Reading pass from pipe
		read(channelPass[0], buffer_pass, sizeof(buffer_pass));
		puts(buffer_pass);

		// Buffer Password
		char buffer_pin[1024];	
		// Reading pin from pipe
		read(channelPin[0], buffer_pin, sizeof(buffer_pin));
		puts(buffer_pin);

		close(channelPass[0]);
		close(channelPin[0]);

		int   pin;
		char* password = (char*) malloc(sizeof(char) * sizeof(buffer_pass));;

		// Couldn't get pin
		if(sscanf(buffer_pin, "%d", &pin) != 1) { 

			//puts("Couldn't execute program."); 
			return 3; 

		// Couldn't get pass
		} else if (sscanf(buffer_pass, "%s", password) != 1) {

			//puts("Couldn't execute program."); 
			return 3; 

		// Could get pin
		} else { 
			
			printf("PIN received from python pipe: %05d\n", pin);
	
			pid_t pid_terminal;		// Process ID 

			char buffer_pin_terminal[1024];  //Buffer do Fifo
			char buffer_pass_terminal[1024]; //Buffer do Fifo

			// Creating a child process
			if ((pid_terminal = fork()) == -1) { 

				//puts("Couldn't create child process."); 
				return 4; 

			}

			// Child process that will execute the python program
			if (pid_terminal == 0) {
				char promptFile[cwd_path_size + 11];
				sprintf(promptFile, "%s/prompt.sh", cwd_path);

				execl("/usr/bin/xterm", "xterm", "-e", "bash", promptFile, pin_pipe_path, (char *) NULL);

			// Parent process that will grab the output from the child
			} else {

				// Reading password from pipe
				int read_fd_pass = open(pin_pipe_path, O_RDONLY);

				read (read_fd_pass, buffer_pass_terminal, sizeof(buffer_pass_terminal));

				close(read_fd_pass);

				// Reading pin from pipe
				int read_fd_pin = open(pin_pipe_path, O_RDONLY);

				read(read_fd_pin, buffer_pin_terminal, sizeof(buffer_pin_terminal));

				close(read_fd_pin);

				
				int   pin_terminal;
				char* pass_terminal = (char*) malloc(sizeof(char) * sizeof(buffer_pass_terminal));

				// Couldn't get password
				if(sscanf(buffer_pass_terminal, "%s", pass_terminal) != 1) 
					return 5;
				
				// Couldn't get pin
				if(sscanf(buffer_pin_terminal, "%d", &pin_terminal) != 1) 
					return 5;

				// PIN from user and auth match
				if (pin_terminal == pin && strcmp(pass_terminal, password) == 0) {
			
					//puts("Access granted");
					return 0;
			
				// PINs don't match
				} else {
			
					//puts("Access denied.");
					return 6;
			
				}

				
			}
			

		}

	}

	return -1;
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
		
		auth_timeout(30);

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
	
	char buff[FILENAME_MAX];
  	getcwd(buff, FILENAME_MAX );

	cwd_path_size = strlen(buff);

	cwd_path = (char*) malloc(cwd_path_size * sizeof(char));
	strcpy(cwd_path, buff);


	pin_pipe_path = (char*) malloc((cwd_path_size + strlen(PIN_PIPE)) * sizeof(char));
	sprintf(pin_pipe_path, "%s%s", buff, PIN_PIPE);

	passwd_path = (char*) malloc((cwd_path_size + strlen(PASSWD_FILE)) * sizeof(char));
	sprintf(passwd_path, "%s%s", buff, PASSWD_FILE);

}


int main(int argc, char *argv[])
{
	initializePaths();

	if (argc > 1 && strcmp(argv[1],"register") == 0 ) {
		
		return auth_register();

	}

	else {
		umask(0);
		
		mkfifo (pin_pipe_path, 0600);

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

usermap:
criar user (tourette, pass, nrTelemovel)
1 - load para a estrutura

Descobrir como mudar pin para ser sempre o mesmo

Descobrir o que é mmap
*/		