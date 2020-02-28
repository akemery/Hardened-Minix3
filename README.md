# HardenedMinix3
Application hardening by adapting an open source operating system Minix3. Ensure the maintenance of services in the presence of failures or transient errors caused by cosmic radiation

# Download
git clone https://github.com/akemery/Hardened-Minix3.git

# Installation
Follow the instructions on https://wiki.minix3.org/doku.php?id=developersguide:crosscompiling to cross the hardened Minix3

# Usage
After compilation, you can start hardened Minix 3
# Compile user space hardened software
Then you have to compile the user space hardened software:
  $ cd /usr/src/test/ 
  $ make
  $ cp hardening /bin/
# Enable hardening

  $ hardening 1
# Enable fault injection
  $ hardening 128

# disable fault injection
  $ hardening 256
# disable hardening 
  $ hardening 2
