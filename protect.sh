#!/bin/bash

SERVER_PATH=/root/shop/server
WALLET_PATH=/root/shop/wallet

 
while true ; do
 
#    用ps获取$PRO_NAME进程数量
  NUM=`ps aux | grep ${SERVER_PATH} | grep -v grep |wc -l`
#  echo $NUM
#    少于1，重启进程
  if [ "${NUM}" -lt "1" ];then
    echo "${SERVER_PATH} was killed"
    nohup ${SERVER_PATH} >> /root/server.log 2>&1 &
#    大于1，杀掉所有进程，重启
  elif [ "${NUM}" -gt "1" ];then
    echo "more than 1 ${SERVER_PATH},killall ${SERVER_PATH}"
    killall -9 $SERVER_PATH
    nohup ${SERVER_PATH} >> /root/server.log 2>&1 &
  fi
#    kill僵尸进程
  NUM_STAT=`ps aux | grep ${SERVER_PATH} | grep T | grep -v grep | wc -l`
 
  if [ "${NUM_STAT}" -gt "0" ];then
    killall -9 ${SERVER_PATH}
    nohup ${SERVER_PATH} >> /root/server.log 2>&1 &
  fi

#    用ps获取$PRO_NAME进程数量
  NUM=`ps aux | grep ${WALLET_PATH} | grep -v grep |wc -l`
#  echo $NUM
#    少于1，重启进程
  if [ "${NUM}" -lt "1" ];then
    echo "${WALLET_PATH} was killed"
    nohup ${WALLET_PATH} >> /root/wallet.log 2>&1 &
#    大于1，杀掉所有进程，重启
  elif [ "${NUM}" -gt "1" ];then
    echo "more than 1 ${WALLET_PATH},killall ${WALLET_PATH}"
    killall -9 $WALLET_PATH
    nohup ${WALLET_PATH} >> /root/wallet.log 2>&1 &
  fi
#    kill僵尸进程
  NUM_STAT=`ps aux | grep ${WALLET_PATH} | grep T | grep -v grep | wc -l`
 
  if [ "${NUM_STAT}" -gt "0" ];then
    killall -9 ${WALLET_PATH}
    nohup ${WALLET_PATH} >> /root/wallet.log 2>&1 &
  fi


done
 
exit 0