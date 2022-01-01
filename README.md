# PSI 
Could you take the techniques used in rootkit malware to make tools for discovering malware?
In this repo I use code from a few different rootkits to built a small kernel module that will log nearly every system operation of interest to `dmesg`. 

Thus far the kernel module will hook system call table for intercepting attepts to open files or change user permissions. It will also enumerate incoming/outgoing packets via network sockets. 

**WARNING** This code is not very stable at the moment, and from my testing has led to unstability of the Ubuntu instance after running for a while. This code is in active development, and I am simply learning, so use at your own risk!


# **DISCLAIMER**
*The contents of this repository are designed purely for educational purposes only. I've designed, tested, and written this code solely for testing on my own personal machines to better understand the techniques and design of Linux based Malware. DO NOT use any of this on equipment that is not yours or do not have permission do so with. I am not responsible for any of the poor choices you may or not make*. 