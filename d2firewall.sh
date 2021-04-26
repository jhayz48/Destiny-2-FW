#!/bin/bash

#credits to @BasRaayman and @inchenzo

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

  #sudo iptables -t nat -F
  #sudo iptables -t mangle -F
  
  sudo iptables -F
  sudo iptables -X

  #allow openvpn
  if ! sudo iptables-save | grep -q "POSTROUTING -s 10.8.0.0/24"; then
    sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
  fi
  sudo iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
  sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
  sudo iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
}

get_platform () {
  local val="psn-4"
  if [ "$1" == "psn" ]; then
    val="psn-4"
  elif [ "$1" == "xbox" ]; then
    val="xboxpwid"
  elif [ "$1" == "steam" ]; then
    val="steamid"
  fi
  echo $val
}

setup () {
  echo "setting up rules"

  reset_ip_tables

  read -p "Enter your platform xbox, psn, steam: " platform
  platform=${platform:-"psn"}

  reject_str=$(get_platform $platform)

  echo $platform > /tmp/data.txt

  default_net="10.8.0.0/24"
  read -p "Enter your network/netmask default is 10.8.0.0/24 for openvpn: " net
  net=${net:-$default_net}
  default_net=$net
  echo $net >> /tmp/data.txt

  echo "How many systems are you using for this?"
  read pnum
  echo $pnum >> /tmp/data.txt

  ids=()
  for ((i = 0; i < pnum; i++))
  do 
    num=$(( $i + 1 ))
    idf="system$num"
    echo "Enter the sniffed ID for System $num"
    read sid
    echo $sid >> /tmp/data.txt
    ids+=( "$idf;$sid" )
  done

  mv /tmp/data.txt ./data.txt

  echo "-m string --string $reject_str --algo bm -j REJECT" > reject.rule
  sudo iptables -I FORWARD -m string --string $reject_str --algo bm -j REJECT
  
  n=${#ids[*]}
  INDEX=1
  for (( i = n-1; i >= 0; i-- ))
  do
    elem=${ids[i]}
    offset=$((n - 2))
    if [ $INDEX -gt $offset ]; then
      inet=$net
    else
      inet="0.0.0.0/0"
    fi
    IFS=';' read -r -a id <<< "$elem"
    sudo iptables -N "${id[0]}"
    sudo iptables -I FORWARD -s $inet -p udp -m string --string "${id[1]}" --algo bm -j "${id[0]}"
    ((INDEX++))
  done
  
  INDEX1=1
  for i in "${ids[@]}"
  do
    IFS=';' read -r -a id <<< "$i"
    INDEX2=1
    for j in "${ids[@]}"
    do
      if [ "$i" != "$j" ]; then
        if [[ $INDEX1 -eq 1 && $INDEX2 -eq 2 ]]; then
          net=$default_net
        elif [[ $INDEX1 -eq 2 && $INDEX2 -eq 1 ]]; then
          net=$default_net
        elif [[ $INDEX1 -gt 2 && $INDEX2 -lt 3 ]]; then
          net=$default_net
        else
          net="0.0.0.0/0"
        fi
        IFS=';' read -r -a idx <<< "$j"
        sudo iptables -A "${id[0]}" -s $net -p udp -m string --string "${idx[1]}" --algo bm -j ACCEPT
      fi
      ((INDEX2++))
    done
    ((INDEX1++))
  done

  iptables-save > /etc/iptables/rules.v4

  echo "setup complete and firewall is active"
}

if [ "$action" == "setup" ]; then
  setup
elif [ "$action" == "stop" ]; then
  echo "disabling reject rule"
  reject=$(<reject.rule)
  sudo iptables -D FORWARD $reject
elif [ "$action" == "start" ]; then
  if ! sudo iptables-save | grep -q "REJECT"; then
    echo "enabling reject rule"
    pos=$(iptables -L FORWARD | grep "system" | wc -l)
    ((pos++))
    reject=$(<reject.rule)
    sudo iptables -I FORWARD $pos $reject
  fi
elif [ "$action" == "add" ]; then
  read -p "Enter the sniffed ID: " id
  if [ ! -z "$id" ]; then
    echo $id >> data.txt
    n=$(sed -n '3p' < data.txt)
    ((n++))
    sed -i "3c$n" data.txt
    bash d2firewall.sh -a setup < data.txt
  fi
elif [ "$action" == "remove" ]; then
  tail -n +4 data.txt | cat -n
  read -p "How many IDs do you want to remove from the end of this list? " num
  head -n -"$num" data.txt > /tmp/data.txt && mv /tmp/data.txt ./data.txt
  n=$(sed -n '3p' < data.txt)
  n=$((n-num))
  sed -i "3c$n" data.txt
  bash d2firewall.sh -a setup < data.txt
elif [ "$action" == "sniff" ]; then
  echo "Have your buddies join you in orbit. You have 30 seconds."
  sys=$(sed -n '1p' < data.txt)
  sys=$(get_platform $sys)
  if [ $sys != "psn-4" ]; then
    echo "only psn is supported atm"
    exit 1
  fi
  bash d2firewall.sh -a stop
  tshark -i tun0 -q -f "udp" -x -Y "frame contains $sys" -T json -e data.data -a duration:10 -x > packets.json
  json=$(cat packets.json)
  for row in $(echo "${json}" | jq -r '.[] | @base64'); do
    _jq() {
     echo ${row} | base64 --decode | jq -r ${1}
    }
    echo $(_jq '._source.layers."data.data"[0]') | xxd -r -p | grep -Pao "$sys.{30}" | grep -o '.......$' >> data.txt
  done
  cat data.txt | awk '!a[$0]++' > /tmp/data.txt && mv /tmp/data.txt ./data.txt
  n=$(tail -n +4 data.txt | wc -l)
  sed -i "3c$n" data.txt
  bash d2firewall.sh -a setup < data.txt
elif [ "$action" == "load" ]; then
  echo "loading rules"
  iptables-restore < /etc/iptables/rules.v4
elif [ "$action" == "reset" ]; then
  echo "erasing all rules"
  reset_ip_tables
fi
