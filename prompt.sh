#!/bin/sh

echo "PASSWORD: "
read password
echo $password > $1

echo "PIN: "
read pin
echo $pin >> $1
