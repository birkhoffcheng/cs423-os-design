# CS 423 MP3

## Design

This kernel module initializes a shared memory region at start. And it can be mapped into a user program's memory space via a character device mmap.

When a process is registered with writing `R <PID>` to the file `/proc/mp3/status`, a kernel thread updates the memory region with the current jiffies count, minor faults, major faults, and utilization every 50 milliseconds.

The memory region is organized as a circular queue. The user program reading the shared memory can sort the data stored it by the jiffies field.

## Usage

### Compile and install
```
make
insmod mp3.ko
```

### Registering processes
Processes have to be registered one at a time.
```
echo 'R <PID>' > /proc/mp3/status
```

### Unregistering processes
Unregister processes one at a time.
```
echo 'U <PID>' > /proc/mp3/status
```

### Reading statistics
```
mknod node c $(grep mp3buf /proc/devices | awk '{print $1}') 0
./monitor
```

### Removal
```
rmmod mp3
```
