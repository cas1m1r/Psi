# PSI 
Could you take the techniques used in rootkit malware to make tools for discovering malware?
In this repo I use code from a few different rootkits to built a small kernel module that will log nearly every system operation of interest to `dmesg`. 

Thus far the kernel module will hook system call table for intercepting attepts to open files or change user permissions. It will also enumerate incoming/outgoing packets via network sockets. 

![testing](https://raw.githubusercontent.com/cas1m1r/Psi/master/testing.gif)


# Logging 
To make this more useful though we need to be able to parse/interpret what is coming from dmesg in real time. This is a bit harder than you'd think though, because we've hooked every action of the VM most things we do will end up appearing in the logs. 

Well a rootkit uses the same idea to hide things like internet traffic, so again borrowing those ideas we can implement the feature of not logging messages from specific IP addresses (in this case local ones). 

Once that works, we can simple setup a listener on our host machine, and launch a shell script in the VM that will build the kernel module, insert it, and then begin piping dmesg back to listening port.

![guest2host](https://github.com/cas1m1r/Psi/raw/master/guest2host.gif)

From here we can start writing code to analyze what's happening in real time!


**WARNING** This code is not very stable at the moment, and from my testing has led to unstability of the Ubuntu instance after running for a while. This code is in active development, and I am simply learning, so use at your own risk!


# **DISCLAIMER**
*The contents of this repository are designed purely for educational purposes only. I've designed, tested, and written this code solely for testing on my own personal machines to better understand the techniques and design of Linux based Malware and Security related Programming topics. DO NOT use any of this on equipment that is not yours or do not have permission do so with. I am not responsible for any of the poor choices you may or not make*. 
