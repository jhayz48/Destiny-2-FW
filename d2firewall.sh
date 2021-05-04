#!/bin/bash
#credits to @BasRaayman and @inchenzo
#dev

INTERFACE="tun0"
DEFAULT_NET="10.8.0.0/24"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

while getopts "a:" opt; do
  case $opt in
    a) action=$OPTARG ;;
    *) echo 'Not a valid command' >&2
       exit 1
  esac
done

reset_ip_tables () {
  service iptables restart

  #reset iptables to default
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT

  iptables -F
  iptables -X

  #allow openvpn
  if ip a | grep -q "tun0"; then
    if ! iptables-save | grep -q "POSTROUTING -s 10.8.0.0/24"; then
      iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    fi
    iptables -A INPUT -p udp -m udp --dport 1194 -j ACCEPT
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT
  fi
}

get_platform_match_str () {
  local val="psn-4"
  if [ "$1" == "psn" ]; then
    val="psn-4"
  elif [ "$1" == "xbox" ]; then
    val="xboxpwid:"
  elif [ "$1" == "steam" ]; then
    val="steamid:"
  fi
  echo $val
}

auto_sniffer () {
  echo -e "${RED}Press any key to stop sniffing. DO NOT CTRL C${NC}"
  sleep 1
  if [ "$1" == "psn" ]; then
    ngrep -l -q -W byline -d $INTERFACE "psn-4" udp | grep --line-buffered -o -P 'psn-4[0]{8}\K[A-F0-9]{7}' | tee -a "$2" &
  elif [ "$1" == "xbox" ]; then
    ngrep -l -q -W byline -d $INTERFACE "xboxpwid:" udp | grep --line-buffered -o -P 'xboxpwid:\K[A-F0-9]{32}' | tee -a "$2" &
  elif [ "$1" == "steam" ]; then
    ngrep -l -q -W byline -d $INTERFACE "steamid:" udp | grep --line-buffered -o -P 'steamid:\K[0-9]{17}' | tee -a "$2" &
  fi
  while [ true ] ; do
    read -t 1 -n 1
    if [ $? = 0 ] ; then
      break
    fi
  done
  pkill -15 ngrep
}

install_dependencies () {
  sysctl -w net.ipv4.ip_forward=1 > /dev/null
  ufw disable > /dev/null

  if ip a | grep -q "tun0"; then
    yn="n"
  else 
    echo -e -n "${GREEN}Would you like to install OpenVPN?${NC} y/n: "
    read yn
    yn=${yn:-"y"}
  fi
  
  if [[ $yn =~ ^(y|yes)$ ]]; then

    echo -e -n "${GREEN}Is this for a local/home setup? ${RED}(Answer no if AWS/VPS)${NC} y/n: "
    read ans
    ans=${ans:-"y"}

    if [[ $ans =~ ^(y|yes)$ ]]; then
      # Put all IPs except for IPv6, loopback and openVPN in an array
      ip_address_list=( $( ip a | grep inet | grep -v -e 10.8. -e 127.0.0.1 -e inet6 | awk '{ print $2 }' | cut -f1 -d"/" ) )
      
      echo "Please enter the number which corresponds to the ip addreses of your device that connects to your local network: "
      i=1
      # Show all addresses in a numbered list
      for address in "${ip_address_list[@]}"; do
        echo "    $i) $address"
        ((i++))
      done
      
      # Have them type out which IP connects to the internet and set IP address based off of that
      read -p "Choice: " ip_line_number
      ip_list_index=$((ip_line_number - 1))
      ip="${ip_address_list[$ip_list_index]}"
      if [ -z $ip ]; then
        echo "Ip does not exist."
        exit 1;
      fi
    else
      ip=$(dig +short myip.opendns.com @resolver1.opendns.com)
    fi;

    echo -e "${RED}Installing dependencies. Please wait while it finishes...${NC}"
    apt-get update > /dev/null
  
    DEBIAN_FRONTEND=noninteractive apt-get -y -q install iptables iptables-persistent ngrep nginx > /dev/null
    service nginx start

    echo -e "${RED}Installing OpenVPN. Please wait while it finishes...${NC}"
    wget -q https://git.io/vpn -O openvpn-ubuntu-install.sh
    chmod +x ./openvpn-ubuntu-install.sh
    (APPROVE_INSTALL=y APPROVE_IP=ip IPV6_SUPPORT=n PORT_CHOICE=1 PROTOCOL_CHOICE=1 DNS=1 COMPRESSION_ENABLED=n CUSTOMIZE_ENC=n CLIENT=client PASS=1 ./openvpn-ubuntu-install.sh) &
    wait;
    cp /root/client.ovpn /var/www/html/client.ovpn
    
    clear
    echo -e "${GREEN}You can download the openvpn config from ${BLUE}http://$ip/client.ovpn"
    echo -e "${GREEN}If you are unable to access this file, you may need to allow/open the http port 80 with your vps provider."
    echo -e "Otherwise you can always run the command cat /root/client.ovpn and copy/paste ALL of its contents in a file on your PC."
    echo -e "It will be deleted automatically in 15 minutes for security reasons."
    echo -e "Be sure to import this config to your router and connect your consoles before proceeding any further.${NC}"
    nohup bash -c 'sleep 900 && service nginx stop && apt remove nginx -y && rm /var/www/html/client.ovpn' &>/dev/null &
  else
    DEBIAN_FRONTEND=noninteractive apt-get -y -q install iptables iptables-persistent ngrep > /dev/null
  fi
  
}

setup () {
  echo -e "${GREEN}Setting up firewall rules.${NC}"
  reset_ip_tables

  read -p "Enter your platform xbox, psn, steam: " platform
  platform=$(echo "$platform" | xargs)
  platform=${platform:-"psn"}

  reject_str=$(get_platform_match_str "$platform")
  echo "$platform" > /tmp/data.txt

  read -p "Enter your network/netmask: " net
  net=$(echo "$net" | xargs)
  net=${net:-$DEFAULT_NET}
  echo "$net" >> /tmp/data.txt

  ids=()
  read -p "Would you like to sniff the ID automatically?(psn/xbox/steam) y/n: " yn
  yn=${yn:-"y"}
  if ! [[ $platform =~ ^(psn|xbox|steam)$ ]]; then
    yn="n"
  fi
  echo "n" >> /tmp/data.txt

  #auto sniffer
  if [[ $yn =~ ^(y|yes)$ ]]; then
    echo -e "${RED}Please have the fireteam leaders join each other in orbit.${NC}"

    auto_sniffer "$platform" "/tmp/data.txt"

    #remove duplicates
    awk '!a[$0]++' /tmp/data.txt > /tmp/temp.txt && mv /tmp/temp.txt /tmp/data.txt

    #get number of accounts
    snum=$(tail -n +4 /tmp/data.txt | wc -l)
    awk "NR==4{print $snum}1" /tmp/data.txt > /tmp/temp.txt && mv /tmp/temp.txt /tmp/data.txt

    #get ids and add to ads array with identifier
    tmp_ids=$(tail -n +5 /tmp/data.txt)
    c=1
    while IFS= read -r line; do 
      idf="system$c"
      ids+=( "$idf;$line" )
      ((c++))
    done <<< "$tmp_ids"
  else #add ids manually
    echo -e "${RED}Please add the 2 fireteam leaders first.${NC}"
    read -p "How many account IDs do you want to add? " snum
    if [ $snum -lt 1 ]; then
      exit 1;
    fi;
    echo $snum >> /tmp/data.txt
    for ((i = 0; i < snum; i++))
    do 
      num=$(( $i + 1 ))
      if [ $num -lt 3 ]; then
        who="Fireteam Leader"
      else
        who="Player"
      fi
      idf="system$num"
      read -p "Enter the sniffed Account ID for $who $num: " sid
      sid=$(echo "$sid" | xargs)
      echo $sid >> /tmp/data.txt
      ids+=( "$idf;$sid" )
    done
  fi;

  mv /tmp/data.txt ./data.txt

  #echo "-m string --string $reject_str --algo bm -j REJECT" > reject.rule
  iptables -I FORWARD -p udp --dport 27000:27200 -m string --string "$reject_str" --algo bm -j REJECT
  
  n=${#ids[*]}
  INDEX=1
  for (( i = n-1; i >= 0; i-- ))
  do
    elem=${ids[i]}
    IFS=';' read -r -a id <<< "$elem"
    offset=$((n - 2))
    if [ $INDEX -gt $offset ]; then
      iptables -N "${id[0]}"
      iptables -I FORWARD -s "$net" -p udp --dport 27000:27200 -m string --string "${id[1]}" --algo bm -j "${id[0]}"
    else
      iptables -I FORWARD -s "$net" -p udp --dport 27000:27200 -m string --string "${id[1]}" --algo bm -j ACCEPT
    fi
    ((INDEX++))
  done
  
  INDEX1=1
  for i in "${ids[@]}"
  do
    if [ $INDEX1 -gt 2 ]; then
      break
    fi
    IFS=';' read -r -a id <<< "$i"
    INDEX2=1
    for j in "${ids[@]}"
    do
      if [ $INDEX2 -gt 2 ]; then
        break
      fi
      if [ "$i" != "$j" ]; then
        IFS=';' read -r -a idx <<< "$j"
        iptables -A "${id[0]}" -s "$net" -p udp --dport 27000:27200 -m string --string "${idx[1]}" --algo bm -j ACCEPT
      fi
      ((INDEX2++))
    done
    ((INDEX1++))
  done

  iptables-save > /etc/iptables/rules.v4

  echo -e "${GREEN}Setup is complete and Matchmaking Firewall is now active.${NC}"
}

if [ "$action" == "setup" ]; then
  if ! command -v ngrep &> /dev/null
  then
      install_dependencies
  fi
  setup
elif [ "$action" == "stop" ]; then
  if iptables-save | grep -q "REJECT"; then
    echo "Matchmaking is no longer being restricted."
    platform=$(sed -n '1p' < data.txt)
    reject_str=$(get_platform_match_str "$platform")
    iptables -D FORWARD -p udp --dport 27000:27200 -m string --string "$reject_str" --algo bm -j REJECT
  fi
elif [ "$action" == "start" ]; then
  if ! iptables-save | grep -q "REJECT"; then
    echo "Matchmaking is now being restricted."
    platform=$(sed -n '1p' < data.txt)
    reject_str=$(get_platform_match_str "$platform")
    pos=$(iptables -L FORWARD | grep -c "system")
    ((pos++))
    iptables -I FORWARD -p udp --dport 27000:27200 -m string --string "$reject_str" --algo bm -j REJECT
  fi
elif [ "$action" == "add" ]; then
  read -p "Enter the sniffed ID: " id
  id=$(echo "$id" | xargs)
  if [ ! -z "$id" ]; then
    echo "$id" >> data.txt
    n=$(sed -n '4p' < data.txt)
    ((n++))
    sed -i "4c$n" data.txt
    read -p "Would you like to enter another ID? y/n " yn
    yn=${yn:-"y"}
    if [[ $yn =~ ^(y|yes)$ ]]; then
      bash d2firewall.sh -a add
    else
      bash d2firewall.sh -a setup < data.txt
    fi
  fi
elif [ "$action" == "remove" ]; then
  list=$(tail -n +5 data.txt | cat -n)
  echo "$list"
  total=$(echo "$list" | wc -l)
  read -p "How many IDs do you want to remove from the end of this list? " num
  if [[ $num -gt 0 && $num -le $total ]]; then
    head -n -"$num" data.txt > /tmp/data.txt && mv /tmp/data.txt ./data.txt
    n=$(sed -n '4p' < data.txt)
    n=$((n-num))
    sed -i "4c$n" data.txt
    bash d2firewall.sh -a setup < data.txt
  fi;
elif [ "$action" == "sniff" ]; then
  platform=$(sed -n '1p' < data.txt)
  if ! [[ $platform =~ ^(psn|xbox|steam)$ ]]; then
      echo "Only psn,xbox, and steam are supported atm."
    exit 1
  fi
  bash d2firewall.sh -a stop

  #auto sniff
  echo -e "${RED}Please have the players join on the fireteam leaders in orbit.${NC}"
  
  auto_sniffer "$platform" "data.txt"

  #remove duplicates
  awk '!a[$0]++' data.txt > /tmp/data.txt && mv /tmp/data.txt ./data.txt

  #update total number of ids
  n=$(tail -n +5 data.txt | wc -l)
  sed -i "4c$n" data.txt

  bash d2firewall.sh -a setup < data.txt
elif [ "$action" == "list" ]; then
  tail -n +5 data.txt | cat -n
elif [ "$action" == "update" ]; then
  wget -q https://raw.githubusercontent.com/cloudex99/Destiny-2-Matchmaking-Firewall/main/d2firewall.sh -O ./d2firewall.sh
  chmod +x ./d2firewall.sh
  echo -e "${GREEN}Script update complete."
  echo -e "Please rerun the initial setup to avoid any issues.${NC}"
elif [ "$action" == "load" ]; then
  echo "Loading firewall rules."
  if [ -f ./data.txt ]; then
      bash d2firewall.sh -a setup < ./data.txt
  else
    iptables-restore < /etc/iptables/rules.v4
  fi
elif [ "$action" == "reset" ]; then
  echo "Erasing all firewall rules."
  reset_ip_tables
fi
