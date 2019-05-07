#!/bin/sh

# run various UNIX commands

time cksum ./*                                    2>>r.out
time md5   ./*                                    2>>r.out
time banner   ./*                                 2>>r.out
time whereis   ls                                 2>>r.out
time basename   /usr/tests/minix-posix/test100    2>>r.out
time ps                                           2>>r.out
time cat ./enable_hardening                       2>>r.out
time env                                          2>>r.out
time cal                                          2>>r.out
time mesg                                         2>>r.out
# time uptime                                     2>>r.out
time dirname   /usr/tests/minix-posix/test100     2>>r.out
time pwd                                          2>>r.out
time whoami                                       2>>r.out
time ls ./*                                       2>>r.out
time uname -a                                     2>>r.out
time ifconfig                                     2>>r.out

