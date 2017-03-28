#! /bin/bash

rm ./client
rm ./server
rm ./wallet
gcc -o wallet ./shop_wallet.c
gcc -o client ./shop_client.c
gcc -o server ./shop_server.c ./dictionary.c
