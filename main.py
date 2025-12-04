import os
import threading

import dos
import nmap
import arp

os.system('clear')

nids="""
========================================================
  ____     __   __________  ________        ______ 
|     \   |  | |___    ___|  |   __  \    /  _____|
|  |\  \  |  |     |  |      |  |  \  \  |  |_____ 
|  | \  \ |  |     |  |      |  |   |  | |______  |
|  |  \  \|  |  ___|  |___   |  |__/  /   _____|  |
|__|   \____ | |__________| _|______ /   |_______/ 

========================================================

    v1.0-cli"""

    
fn="""
 __________________________________________________________________
 ------------------------------------------------------------------
 || DOS detection               || ARP Spoofing                  ||
 || PORT scanning               ||                               ||
 __________________________________________________________________
 ------------------------------------------------------------------
 
"""

print(nids)
print(fn)


thread1=threading.Thread(target=dos.start_dos)
thread2=threading.Thread(target=nmap.start_nmap)
thread3=threading.Thread(target=arp.start_arp)

thread1.start()
thread2.start()
thread3.start()

thread1.join()
thread2.join()
thread3.join()
