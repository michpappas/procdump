# procdump

Reconstruct ELF executable object from a process

procdump will fail if yama is enabled. To disable yama:
```
echo 0 > /proc/sys/kernel/yama/ptrace_scope
```
procdump does not work with processes loaded from binaries compiled with PIE. To disable PIE:
```
gcc -no-pie
```
