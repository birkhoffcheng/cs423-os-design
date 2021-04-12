#ifndef _SECURITY_MP4_GIVEN_H
#define _SECURITY_MP4_GIVEN_H

#include <uapi/linux/xattr.h>
#include <linux/fs.h>

/* mp4 extended attributed */
#define XATTR_MP4_SUFFIX "mp4"
#define XATTR_NAME_MP4 XATTR_SECURITY_PREFIX XATTR_MP4_SUFFIX

/* mp4 labels along with their semantics */
#define MP4_NO_ACCESS	0	/* may not be accessed by target,
				 * but may by everyone else */
#define MP4_READ_OBJ	1	/* object may be read by anyone */
#define MP4_READ_WRITE	2	/* object may read/written/appended by the target,
				 * but can only be read by others */
#define MP4_WRITE_OBJ	3	/* object may be written/appended by the target,
				 * but not read, and only read by others */
#define MP4_EXEC_OBJ	4	/* object may be read and executed by all */

/*
 * NOTE: FOR DIRECTORIES, ONLY CHECK ACCESS FOR THE TARGET SID, ALL OTHER NON
 * TARGET PROCESSES SHOULD DEFAULT TO THE REGULAR LINUX ACCESS CONTROL
 */
#define MP4_READ_DIR	5	/* for directories that can be read/exec/access
				 * by all */
#define MP4_RW_DIR	6	/* for directory that may be modified by the
				 * target program */

/* the target mp4 sid label */
#define MP4_TARGET_SID 7

/**
 * Our custom mp4 security label on tasks and inodes
 * @mp4_flags: the sid values specific to an object/task
 */
struct mp4_security {
	int mp4_flags;

	/* add any supporting definitions here if needed
	 * ...
	 */
};

/**
 * __cred_ctx_to_id - Get the label id from an attribute context
 *
 * @cred_ctx: buffer containing the attribute name
 *
 * return the sid of the attribute's label, NO_ACCESS if not found
 *
 */
static inline int __cred_ctx_to_sid(const char *cred_ctx)
{
	/*
	 * Go through the possible values and return
	 * the appropriate one.
	 */
	if (strcmp(cred_ctx, "read-only") == 0)
		return MP4_READ_OBJ;
	else if (strcmp(cred_ctx, "read-write") == 0)
		return MP4_READ_WRITE;
	else if (strcmp(cred_ctx, "exec") == 0)
		return MP4_EXEC_OBJ;
	else if (strcmp(cred_ctx, "target") == 0)
		return MP4_TARGET_SID;
	else if (strcmp(cred_ctx, "write-only") == 0)
		return MP4_WRITE_OBJ;
	else if (strcmp(cred_ctx, "dir") == 0)
		return MP4_READ_DIR;
	else if (strcmp(cred_ctx, "dir-write") == 0)
		return MP4_RW_DIR;
	else
		return MP4_NO_ACCESS;
}

/**
 * mp4_should_skip_path - Check if path to object is to be skipped
 *
 * @dir: the pathname of the object to check for
 *
 * returns 1 if should skip, 0 otherwise
 *
 */
static inline int mp4_should_skip_path(const char *dir)
{
	if (!strncmp(dir, "/dev", 4) ||
	    !strncmp(dir, "/proc", 5) ||
	    !strncmp(dir, "/lib", 4) ||
	    !strncmp(dir, "/events", 7) ||
	    !strncmp(dir, "/mnt", 4) ||
	    !strncmp(dir, "/run", 4) ||
	    !strncmp(dir, "/lvm", 4) ||
	    !strncmp(dir, "/conf", 5) ||
	    !strncmp(dir, "/usr", 4) ||
	    !strncmp(dir, "/bin", 4) ||
	    !strcmp(dir, "/"))
		return 1;

	return 0;
}


/* NOTE: operation masks can be found in linux/fs.h */

#endif /* _SECURITY_MP4_GIVEN_H */
