#!/bin/bash
# A script that will install cuckoo and all its needed dependencies
# In the event volatility is wanted (for this project it is not, please follow the steps to install it at https://github.com/volatilityfoundation/volatility)
# Also operating under the assumption that virtualbox is what is going to be used

#----------------------------------------------------------------------------------------------------------------------------
# Dependency installs
#----------------------------------------------------------------------------------------------------------------------------
# Initial developer toolsets and python requirements
sudo apt-get install python python-pip python-dev libffi-dev libssl-dev -y
sudo apt-get install python-virtualenv python-setuptools -y
sudo apt-get install libjpeg-dev zlib1g-dev swig -y
sudo apt-get install mongodb -y
sudo apt-get install postgresql libpq-dev -y
sudo apt-get install qemu-kvm libvirt-bin ubuntu-vm-builder bridge-utils python-libvirt -y
sudo python2 -m pip install XenAPI 

# Install of virtualbox (for virtualisation)
echo deb http://download.virtualbox.org/virtualbox/debian xenial contrib | sudo tee -a /etc/apt/sources.list.d/virtualbox.list
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
sudo apt-get update -y
sudo apt-get install virtualbox-5.2 -y

# Install of tcpDump (for network analysis)
sudo apt-get install tcpdump apparmor-utils 
sudo aa-disable /usr/sbin/tcpdump 

# Here we separate user perms for our cuckoo user
sudo groupadd pcap 
sudo usermod -a -G pcap cuckoo 
sudo chgrp pcap /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo apt-get install libcap2-bin 

# Install swig for m2crypto requirements and finally guacd
sudo apt-get install swig -y
sudo pip install m2crypto==0.24.0 
sudo apt install libguac-client-rdp0 libguac-client-vnc0 libguac-client-ssh0 guacd

#----------------------------------------------------------------------------------------------------------------------------
# Installing cuckoo 
#----------------------------------------------------------------------------------------------------------------------------
# Add the user "cuckoo" and add it ias a user for virtualbox
sudo adduser cuckoo
sudo usermod -a -G vboxusers cuckoo

# Create a virtual env and activate it before installing cuckoo
virtualenv venv
. venv/bin/activate
pip install -U pip setuptools
pip install -U cuckoo