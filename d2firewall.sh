#!/bin/bash

#credits to @basraayan and @inchenzo

while getopts "a:" opt; do
  case $opt in
    a) action=$OPTARG ;;
    *) echo 'error' >&2
       exit 1
  esac
done

reset_ip_tables () {
  #reset iptables to default
  sudo iptables -P INPUT ACCEPT
  sudo iptables -P FORWARD ACCEPT
  sudo iptables -P OUTPUT ACCEPT

  sudo iptables -t nat -F
  sudo iptables -t mangle -F
  sudo iptables -F
  sudo iptables -X

  #allow openvpn
  sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
  sudo iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
}

setup () {
  echo "setting up rules"

  reset_ip_tables

  read -p "Enter your platform xbox, psn, steam:" platform
  platform=${platform:-"psn"}
  if [ "$platform" == "psn" ]; then
    reject_str="psn-4"
  elif [ "$platform" == "xbox" ]; then
    reject_str="xboxpim"
  elif [ "$platform" == "steam" ]; then
    reject_str="steamid"
  else
    reject_str="psn-4"
  fi

  default_net="10.8.0.0/24"
  read -p "Enter your network/netmask default is 10.8.0.0/24 for openvpn:" net
  net=${net:-$default_net}
  echo "How many systems are you using for this?"
  read pnum

  ids=()
  for ((i = 0; i < pnum; i++))
  do 
    num=$(( $i + 1 ))
    idf="system$num"
    echo "Enter the sniffed ID for System $num"
    read sid
    ids+=( "$idf:$sid" )
  done

  for i in "${ids[@]}"
  do
    IFS=':' read -r -a id <<< "$i"
    sudo iptables -N "${id[0]}"
    sudo iptables -A FORWARD -s $net -p udp -m string --string "${id[1]}" --algo bm -j "${id[0]}"
    for j in "${ids[@]}"
    do
      if [ "$i" != "$j" ]; then
        IFS=':' read -r -a idx <<< "$j"
        sudo iptables -A "${id[0]}" -s $net -p udp -m string --string "${idx[1]}" --algo bm -j ACCEPT
      fi
    done
  done
  echo "FORWARD -s $net -m string --string $reject_str --algo bm -j REJECT" > reject.rule
  sudo iptables -A FORWARD -s $net -m string --string $reject_str --algo bm -j REJECT

  sudo iptables-save > /etc/iptables/default.v4
}

if [ "$action" == "setup" ]; then
  setup
elif [ "$action" == "stop" ]; then
  echo "disabling reject rule"
  reject=$(<reject.rule)
  sudo iptables -D $reject
elif [ "$action" == "start" ]; then
  if ! sudo iptables-save | grep -q "REJECT"; then
    echo "enabling reject rule"
    reject=$(<reject.rule)
    sudo iptables -A $reject
  fi
elif [ "$action" == "load" ]; then
  echo "loading rules"
  sudo iptables-restore < /etc/iptables/default.v4
elif [ "$action" == "reset" ]; then
  echo "erasing all rules"
  reset_ip_tables
fi
