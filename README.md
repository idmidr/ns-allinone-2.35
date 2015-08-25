# ns-2.35 with IDMIDR patched.
Installation:
* Open a terminal and paste the following commands one by one:
  - `cd`
  - `sudo apt-get update && sudo apt-get install build-essential autoconf automake libxmu-dev gcc git`
  - `git clone https://github.com/idmidr/ns-allinone-2.35.git`
  - `cd ns-allinone-2.35/`
  - `./install`
* Paste the following lines at the end of `~/.bashrc` file (you can open and edit that file pasting the `gedit ~/.bashrc` command in your terminal):
  - `export PATH=$PATH:~/ns-allinone-2.35/bin:~/ns-allinone-2.35/tcl8.5.10/unix:~/ns-allinone-2.35/tk8.5.10/unix`
  - `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/ns-allinone-2.35/otcl-1.14:~/ns-allinone-2.35/lib`
  - `export TCL_LIBRARY=$TCL_LIB:~/ns-allinone-2.35/tcl8.5.10/library:/usr/lib`
* Paste the following command in your terminal:
  - `source ~/.bashrc`

An example of how to simulate IMDIR and Anycast AODV:`~/ns-allinone-2.35/ns-2.35/idmidr_example`

ns-2.35 with IDMIDR patched was tested on Ubuntu 10.04, 11.04 and Debian 6. A pre-built virtual machine that contains ns-2 with IDMIDR can be obtained from:  [http://www.prime.cic.ipn.mx/~je/idmidr/anycast/virtual_machine.tar.gz](http://www.prime.cic.ipn.mx/~je/idmidr/anycast/virtual_machine.tar.gz)
