# CS 423 MP1
## User time reader

Registers processes and displays user time for each process.

## Usage
### Install
```
make
insmod mp1.ko
```

### Registration
```
echo <PID> > /proc/mp1/status
```

### Check user time
```
cat /proc/mp1/status
```

### Removal
```
rmmod mp1
```
