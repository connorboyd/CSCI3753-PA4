/*
  Connor Boyd
  CSCI 3753
  Spring 2014
  pa4-encfs.c

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

*/

#define ENCRYPT 1
#define DECRYPT 0
#define PASS_THROUGH -1

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 700
#endif

#include "aes-crypt.h"

#include <limits.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

 #include "aes-crypt.h"

typedef struct {
	char *rootdir;
	char *encryptionKey;
} encfs_data;

static void encfs_fullpath(char fpath[PATH_MAX], const char *path)
{
	encfs_data *data = (encfs_data *) (fuse_get_context()->private_data);
	strcpy(fpath, data->rootdir);
	strncat(fpath, path, PATH_MAX);
}

static int encfs_getattr(const char *path, struct stat *stbuf)
{
	int res;

	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int encfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_mkdir(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_symlink(const char *from, const char *to)
{
	int res;
	char from_fpath[PATH_MAX];
	encfs_fullpath(from_fpath, from);

	char to_fpath[PATH_MAX];
	encfs_fullpath(to_fpath, to);

	res = symlink(from_fpath, to_fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rename(const char *from, const char *to)
{
	int res;
	char from_fpath[PATH_MAX];
	encfs_fullpath(from_fpath, from);

	char to_fpath[PATH_MAX];
	encfs_fullpath(to_fpath, to);

	res = rename(from_fpath, to_fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_link(const char *from, const char *to)
{
	int res;
	char from_fpath[PATH_MAX];
	encfs_fullpath(from_fpath, from);

	char to_fpath[PATH_MAX];
	encfs_fullpath(to_fpath, to);

	res = link(from_fpath, to_fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chmod(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	
	FILE *memFile;
	char *memText;
	size_t memSize;

	encfs_data *fuseData = 	(encfs_data *) (fuse_get_context()->private_data);
	char *key = fuseData->encryptionKey;

	// int fd;		//Result of open call
	int res;	//result of pread call
	char fpath[PATH_MAX];	//holds full path
	encfs_fullpath(fpath, path);	//Turns path into full path 
	(void) fi;		//Fuse file info?
	FILE *f;
	f = fopen(fpath, "r");
	// fd = open(fpath, O_RDONLY);
	// if (fd == -1)
	// 	return -errno;

	memFile = open_memstream(&memText, &memSize);

	do_crypt(f, memFile, DECRYPT, key);

	res = pread(memFile, buf, size, offset);
	if (res == -1)
		res = -errno;

	// close(fd);
	fclose(f);

	fflush(memFile);
	fseek(memFile, offset, SEEK_SET);
	res = fread(buf, 1, size, memFile);
	fclose(memFile);

	return res;
}

static int encfs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	// int fd;
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	(void) fi;

	encfs_data *fuseData = 	(encfs_data *) (fuse_get_context()->private_data);
	char *key = fuseData->encryptionKey;

	FILE *f, *memFile;
	char *memText;
	size_t memSize;

	memFile = open_memstream(&memText, &memSize);
	f = fopen(fpath, "r");

	do_crypt(f, memFile, DECRYPT, key);
	fclose(f);

	fseek(memFile, offset, SEEK_SET);
	res = fwrite(buf, 1, size, memFile);

	fflush(memFile);
	f = fopen(fpath, "w");
	fseek(memFile, 0, SEEK_SET);
	do_crypt(memFile, f, ENCRYPT, key);
	fclose(memFile);
	fclose(f);



	// fd = open(fpath, O_WRONLY);
	// if (fd == -1)
	// 	return -errno;

	// res = pwrite(fd, buf, size, offset);
	// if (res == -1)
	// 	res = -errno;

	// close(fd);
	return res;
}

static int encfs_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
    int res;
    res = creat(fpath, mode);

    if(res == -1)
		return -errno;

    close(res);

    return 0;
}


static int encfs_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int encfs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int encfs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int encfs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
	encfs_fullpath(fpath, path);
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations encfs_oper = {
	.getattr	= encfs_getattr,
	.access		= encfs_access,
	.readlink	= encfs_readlink,
	.readdir	= encfs_readdir,
	.mknod		= encfs_mknod,
	.mkdir		= encfs_mkdir,
	.symlink	= encfs_symlink,
	.unlink		= encfs_unlink,
	.rmdir		= encfs_rmdir,
	.rename		= encfs_rename,
	.link		= encfs_link,
	.chmod		= encfs_chmod,
	.chown		= encfs_chown,
	.truncate	= encfs_truncate,
	.utimens	= encfs_utimens,
	.open		= encfs_open,
	.read		= encfs_read,
	.write		= encfs_write,
	.statfs		= encfs_statfs,
	.create     = encfs_create,
	.release	= encfs_release,
	.fsync		= encfs_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= encfs_setxattr,
	.getxattr	= encfs_getxattr,
	.listxattr	= encfs_listxattr,
	.removexattr= encfs_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	printf("argv[1] = %s\n",argv[1] );
	printf("argv[2] = %s\n",argv[2] );
	printf("argv[3] = %s\n",argv[3] );
	printf("argv[4] = %s\n",argv[4] );
	
	encfs_data data;
	data.rootdir = realpath(argv[2], NULL);
	data.encryptionKey = argv[1];
	printf("encryptionKey = %s\n", data.encryptionKey);
	printf("rootdir = %s\n", data.rootdir);
	umask(0);
	return fuse_main(argc-2, argv+2, &encfs_oper, &data);
}
