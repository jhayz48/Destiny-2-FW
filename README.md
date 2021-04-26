# Destiny-2-Matchmaking-Firewall-Iptables

## Download
#### Clone repo or run this command: 
```wget -q https://raw.githubusercontent.com/cloudex99/Destiny-2-Matchmaking-Firewall/main/d2firewall.sh -O ./d2firewall.sh```
## Usage
#### Setup: initial setup
``` bash d2firewall.sh -a setup ```
#### Stop: disable the reject rule 
``` bash d2firewall.sh -a stop ```
#### Start: enable the reject rule
``` bash d2firewall.sh -a start ```
#### Add: add a sniffed id to your firewall
``` bash d2firewall.sh -a add ```
#### Remove: remove ids from the end of the list
``` bash d2firewall.sh -a remove ```
#### Sniff: Auto sniff for psn. Once run your buddies must join within 60 seconds. Should only be run after initial setup. Install jq prior to using this with ```apt install jq```.
``` bash d2firewall.sh -a sniff ```
#### Load: load the saved iptables firewall configuration (you don't need to worry about this)
``` bash d2firewall.sh -a load ```
#### Reset: reset iptables to default
``` bash d2firewall.sh -a reset ```

### Details:
#### This script is written to work in a Ubuntu system with an iptables firewall and openvpn. 
#### The first two systems added must be the hosts of each fireteam.
#### Every time you want to invite players to the fireteam you must stop the firewall first. Once the fireteam is ready start the firewall back up.
#### This is tested to work on PSN, it may work on Xbox and Steam. If you encounter any issues feel free to make an issue.
#### Also please do not run this on your personal computer it will clobber your firewall rules. It is meant to be run on an isolated vps/cloud instance.
#### Credits to inchenzo & BasRaayman.
