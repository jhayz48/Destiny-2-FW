# Destiny-2-Matchmaking-Firewall-Iptables

## Download
#### Clone repo or run this command: 
```wget -q https://raw.githubusercontent.com/cloudex99/Destiny-2-Matchmaking-Firewall/main/d2firewall.sh -O ./d2firewall.sh```
## Usage
#### Setup: initial setup
``` sudo bash d2firewall.sh -a setup ```
#### Stop: Enables public matchmaking 
``` sudo bash d2firewall.sh -a stop ```
#### Start: Disables public matchmaking
``` sudo bash d2firewall.sh -a start ```
#### Add: add a sniffed id to your firewall
``` sudo bash d2firewall.sh -a add ```
#### Remove: remove ids from the end of the list
``` sudo bash d2firewall.sh -a remove ```
#### Sniff: Auto sniff for psn. (You must add your 2 host consoles prior to running this)
``` sudo bash d2firewall.sh -a sniff ```
#### List: List the current accounts
``` sudo bash d2firewall.sh -a list ```
#### Update: Update the script to the newest version.
``` sudo bash d2firewall.sh -a update ```
#### Load: Load the saved rules
``` sudo bash d2firewall.sh -a load ```
#### Reset: Reset iptables to default
``` sudo bash d2firewall.sh -a reset ```

### Details:
#### This script is written to work in a Ubuntu system with an iptables firewall and openvpn.
#### The first two systems added must be the hosts of each fireteam.
#### Every time you want to invite players to the fireteam you must stop the firewall first. Sniff the IDs of the new members and add them. Once the fireteam is ready start the firewall back up. (This is not necessary if you use auto sniffing.)
#### This is tested to work on PSN, Xbox and Steam. If you encounter any issues feel free to make an issue.
#### Also please do not run this on your personal computer it will clobber your firewall rules. It is meant to be run on an isolated vps/cloud instance.
#### Credits to inchenzo & BasRaayman.
