# Destiny-2-Matchmaking-Firewall-Iptables

## Download
#### Clone repo or run this command: 
```wget -q https://raw.githubusercontent.com/cloudex99/Destiny-2-Matchmaking-Firewall/main/d2firewall.sh -O ./d2firewall.sh```
## Usage
#### Setup: initial setup
``` sudo bash d2firewall.sh -a setup ```
#### Stop: disable the reject rule 
``` sudo bash d2firewall.sh -a stop ```
#### Start: enable the reject rule
``` sudo bash d2firewall.sh -a start ```
#### Add: add a sniffed id to your firewall (run initial setup again before runing this for the first time)
``` sudo bash d2firewall.sh -a add ```
#### Remove: remove ids from the end of the list (run initial setup again before runing this for the first time)
``` sudo bash d2firewall.sh -a remove ```
#### Sniff: Auto sniff for psn. Once run your buddies must join within 60 seconds. (run initial setup again before runing this for the first time)
``` sudo bash d2firewall.sh -a sniff ```
#### Load: load the saved iptables firewall configuration (you don't need to worry about this)
``` sudo bash d2firewall.sh -a load ```
#### Reset: reset iptables to default
``` sudo bash d2firewall.sh -a reset ```

### Details:
#### This script is written to work in a Ubuntu system with an iptables firewall and openvpn. 
#### The first two systems added must be the hosts of each fireteam.
#### Every time you want to invite players to the fireteam you must stop the firewall first. Sniff the IDs of the new members and add them. Once the fireteam is ready start the firewall back up. (This step is not necessary if you use auto sniffing.)
#### This is tested to work on PSN, it may work on Xbox and Steam. If you encounter any issues feel free to make an issue.
#### Also please do not run this on your personal computer it will clobber your firewall rules. It is meant to be run on an isolated vps/cloud instance.
#### Credits to inchenzo & BasRaayman.
