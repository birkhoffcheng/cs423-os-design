#define pr_fmt(fmt) "cs423_mp4: " fmt
#define XATTR_LEN 64
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/binfmts.h>
#include "mp4_given.h"

/**
 * get_inode_sid - Get the inode mp4 security label id
 *
 * @inode: the input inode
 *
 * @return the inode's security id if found.
 *
 */
static int get_inode_sid(struct inode *inode)
{
	/*
	 * Add your code here
	 * ...
	 */
	char *cred_ctx;
	int ret = 0;
	struct dentry *dentry;

	if (!inode || !inode->i_op || !inode->i_op->getxattr) {
		ret = -1;
		goto out;
	}

	dentry = d_find_alias(inode);
	if (!dentry) {
		pr_err("get_inode_sid: Dentry NULL\n");
		ret = -EFAULT;
		goto out;
	}

	cred_ctx = kzalloc(XATTR_LEN, GFP_NOFS);
	if (!cred_ctx) {
		pr_err("get_inode_sid: No Memory\n");
		ret = -ENOMEM;
		goto out_dput;
	}

	ret = inode->i_op->getxattr(dentry, XATTR_NAME_MP4, cred_ctx, XATTR_LEN);
	if (ret < 0) {
		ret = 0;
		goto out_kfree;
	}

	ret = __cred_ctx_to_sid(cred_ctx);

out_kfree:
	kfree(cred_ctx);
out_dput:
	dput(dentry);
out:
	return ret;
}

static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp);
/**
 * mp4_bprm_set_creds - Set the credentials for a new task
 *
 * @bprm: The linux binary preparation structure
 *
 * returns 0 on success.
 */
static int mp4_bprm_set_creds(struct linux_binprm *bprm)
{
	/*
	 * Add your code here
	 * ...
	 */
	int sid = get_inode_sid(bprm->file->f_inode);
	struct mp4_security *msec = bprm->cred->security;
	if (!msec)
		mp4_cred_alloc_blank(bprm->cred, GFP_KERNEL);
	if (sid == MP4_TARGET_SID)
		msec->mp4_flags = MP4_TARGET_SID;
	return 0;
}

/**
 * mp4_cred_alloc_blank - Allocate a blank mp4 security label
 *
 * @cred: the new credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	/*
	 * Add your code here
	 * ...
	 */
	struct mp4_security *msec = kzalloc(sizeof(struct mp4_security), gfp);
	if (!msec)
		return -ENOMEM;

	cred->security = msec;
	return 0;
}


/**
 * mp4_cred_free - Free a created security label
 *
 * @cred: the credentials struct
 *
 */
static void mp4_cred_free(struct cred *cred)
{
	/*
	 * Add your code here
	 * ...
	 */
	kfree(cred->security);
}

/**
 * mp4_cred_prepare - Prepare new credentials for modification
 *
 * @new: the new credentials
 * @old: the old credentials
 * @gfp: the atomicity of the memory allocation
 *
 */
static int mp4_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
	struct mp4_security *msec;
	if (old && old->security) {
		msec = kmemdup(old->security, sizeof(struct mp4_security), gfp);
	}
	else {
		mp4_cred_alloc_blank(new, gfp);
		return 0;
	}
	if (!msec)
		return -ENOMEM;

	if (new) new->security = msec;
	return 0;
}

/**
 * mp4_inode_init_security - Set the security attribute of a newly created inode
 *
 * @inode: the newly created inode
 * @dir: the containing directory
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * returns 0 if all goes well, -ENOMEM if no memory, -EOPNOTSUPP to skip
 *
 */
static int mp4_inode_init_security(struct inode *inode, struct inode *dir,
				   const struct qstr *qstr,
				   const char **name, void **value, size_t *len)
{
	/*
	 * Add your code here
	 * ...
	 */
	struct mp4_security *msec = current_cred()->security;
	if (msec->mp4_flags == MP4_TARGET_SID) {
		*name = kstrdup(XATTR_MP4_SUFFIX, GFP_KERNEL);
		*value = kstrdup("read-write", GFP_KERNEL);
		*len = strlen(*value);
	}
	return 0;
}

/**
 * mp4_has_permission - Check if subject has permission to an object
 *
 * @ssid: the subject's security id
 * @osid: the object's security id
 * @mask: the operation mask
 *
 * returns 0 is access granter, -EACCES otherwise
 *
 */
#define PERMIT 0
#define DENY -EACCES
static int mp4_has_permission(int ssid, int osid, int mask)
{
	/*
	 * Add your code here
	 * ...
	 */
	int ret;

	mask &= (MAY_READ | MAY_WRITE | MAY_EXEC | MAY_APPEND | MAY_ACCESS);
	if (!mask) {
		ret = PERMIT;
		goto out;
	}

	if (ssid != MP4_TARGET_SID) {
		if (osid == MP4_NO_ACCESS)
			ret = PERMIT;
		else if (osid == MP4_EXEC_OBJ)
			if (mask & ~(MAY_READ | MAY_EXEC))
				ret = DENY;
			else
				ret = PERMIT;
		else if (mask & ~(MAY_READ | MAY_ACCESS))
			ret = DENY;
		else
			ret = PERMIT;
		goto out;
	}

	switch (osid)
	{
	case MP4_NO_ACCESS:
		ret = DENY;
		break;

	case MP4_READ_OBJ:
		if (mask & ~MAY_READ)
			ret = DENY;
		else
			ret = PERMIT;
		break;

	case MP4_READ_WRITE:
		if (mask & ~(MAY_READ | MAY_WRITE | MAY_APPEND))
			ret = DENY;
		else
			ret = PERMIT;
		break;

	case MP4_WRITE_OBJ:
		if (mask & ~(MAY_WRITE | MAY_APPEND))
			ret = DENY;
		else
			ret = PERMIT;
		break;

	case MP4_EXEC_OBJ:
		if (mask & ~(MAY_READ | MAY_EXEC))
			ret = DENY;
		else
			ret = PERMIT;
		break;

	case MP4_READ_DIR:
		if (mask & ~(MAY_READ | MAY_EXEC | MAY_ACCESS))
			ret = DENY;
		else
			ret = PERMIT;
		break;

	case MP4_RW_DIR:

	default:
		ret = PERMIT;
		break;
	}

out:
	return ret;
}

/**
 * mp4_inode_permission - Check permission for an inode being opened
 *
 * @inode: the inode in question
 * @mask: the access requested
 *
 * This is the important access check hook
 *
 * returns 0 if access is granted, -EACCES otherwise
 *
 */
static int mp4_inode_permission(struct inode *inode, int mask)
{
	/*
	 * Add your code here
	 * ...
	 */
	int ssid, osid, ret = 0;
	char *path, *buf;
	struct mp4_security *msec;
	struct dentry *dentry;

	if (!inode) {
		pr_err("inode_permission: Inode NULL\n");
		goto out;
	}

	dentry = d_find_alias(inode);
	if (!dentry) {
		pr_err("inode_permission: Can't find dentry\n");
		goto out;
	}

	buf = kzalloc(PATH_MAX, GFP_KERNEL);
	if (!buf) {
		pr_err("inode_permission: No Memory\n");
		goto out_dput;
	}

	path = dentry_path_raw(dentry, buf, PATH_MAX);
	if (IS_ERR(path))
		goto out_kfree;

	if (mp4_should_skip_path(path))
		goto out_kfree;

	osid = get_inode_sid(inode);
	if (osid < 0)
		goto out_kfree;

	msec = current_cred()->security;
	ssid = msec->mp4_flags;
	ret = mp4_has_permission(ssid, osid, mask);
	if (ret) {
		pr_info("ssid %d, osid %d, request 0x%x has been denied\n", ssid, osid, mask);
	}

out_kfree:
	kfree(buf);
out_dput:
	dput(dentry);
out:
	return ret;
}


/*
 * This is the list of hooks that we will using for our security module.
 */
static struct security_hook_list mp4_hooks[] = {
	/*
	 * inode function to assign a label and to check permission
	 */
	LSM_HOOK_INIT(inode_init_security, mp4_inode_init_security),
	LSM_HOOK_INIT(inode_permission, mp4_inode_permission),

	/*
	 * setting the credentials subjective security label when laucnhing a
	 * binary
	 */
	LSM_HOOK_INIT(bprm_set_creds, mp4_bprm_set_creds),

	/* credentials handling and preparation */
	LSM_HOOK_INIT(cred_alloc_blank, mp4_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free, mp4_cred_free),
	LSM_HOOK_INIT(cred_prepare, mp4_cred_prepare)
};

static __init int mp4_init(void)
{
	/*
	 * check if mp4 lsm is enabled with boot parameters
	 */
	if (!security_module_enable("mp4"))
		return 0;

	pr_info("mp4 LSM initializing..");

	/*
	 * Register the mp4 hooks with lsm
	 */
	security_add_hooks(mp4_hooks, ARRAY_SIZE(mp4_hooks));

	return 0;
}

/*
 * early registration with the kernel
 */
security_initcall(mp4_init);
