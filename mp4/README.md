# CS 423 MP4 LSM
## Design
The Linux Security Module initializes every running task with a blank credential, and check the inode the program is launched from. If the running binary has the extended attribute `security.mp4` set to `target`, our module will enforce access control on it.

When a target program accesses a file with no label, the request will be denied. If a target program accesses a file with labels allowing the access, the request will be permitted.

For each denied access, a record of the request will be kept in the kernel log.

For unlabeled programs, we do not enforce any policy on unlabeled files, but will only allow read on labeled files. This is so that we don't have to label everything in the filesystem and don't prevent critical processes from accessing the resources they need.

## Usage
To use in Linux 4.4, enable the `mp4` security module in the config and append `security=mp4` to the kernel command line.
