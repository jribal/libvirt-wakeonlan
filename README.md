INTRODUCTION
============
libvirt-wakeonlan is a daemon which listens for wake on lan packets and starts libvirt based virtual machines. 

INSTALLATION
============

SOURCE INSTALL
==============

Clone the git repo:

```
git clone git://github.com/simoncadman/libvirt-wakeonlan.git

cd libvirt-wakeonlan/
./configure
make install
```
Run the daemon

```
systemctl start libvirt-wakeonlan
```

CONFIGURATION
=============

libvirt-wakeonlan listens on eth0 by default for Wake-on-lan packets, to change this, there is a configuration file for the libvirt-wakeonlan 
service ( in /etc/conf.d/ on Gentoo, /etc/sysconfig on Fedora and /etc/default on Debian ), within it is a parameter called 
"LIBVIRTDWOL_INTERFACE" which specifies the interface used. 

DEVELOPING
==========

Before commiting to the git repository you should set up the pre-commit hook, this ensures the version numbers in the scripts are updated:

ln -s ../../pre-commit.py .git/hooks/pre-commit

Copyright
=========

Software and icon are copyright Simon Cadman and licenced under GNU GPL v3 ( http://www.gnu.org/licenses/gpl.html ).
