#!/bin/bash

make -f Makefile
LD_PRELOAD=./logger.so ./test_aclog "$1" "$2"

for f in "$1"/*.txt 
do
  var0="$f"
  suffix=".txt"
  var01=${var0%"$suffix"}
  var1=".encrypt"
  var2="$var01$var1"
  export LD_PRELOAD=./logger.so
  openssl enc -aes-256-ecb -in "$f" -out "$var2" -k 1234
  rm "$f"
done
rm "access_control_logfile.encrypt"
LD_PRELOAD=./logger.so ./test_aclog "$1" "$2"

