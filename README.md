# Destiny-2-Matchmaking-Firewall-Iptables

## Download
#### Clone repo or run this command: wget -q https://raw.githubusercontent.com/cloudex99/Destiny-2-Matchmaking-Firewall/main/d2firewall.sh -O ./d2firewall.sh
## Usage
#### Setup: Initial setup
``` bash d2firewall.sh -a setup ```
#### Stop: Disables the reject rule 
``` bash d2firewall.sh -a stop ```
#### Start: Enables the reject rule
``` bash d2firewall.sh -a start ```
#### Load: Loads the saved iptables firewall configuration
``` bash d2firewall.sh -a load ```
#### Reset: Reset iptables to default
``` bash d2firewall.sh -a reset ```

### Details:
#### This script is written to work in a Ubuntu system with an iptables firewall and openvpn. 
#### Every time you want to invite players to the fireteam you must stop the firewall first. Once the fireteam is ready start the firewall back up.
#### This is tested to work on PSN, it may work on Xbox and Steam. If you encounter any issues feel free to make an issue.
#### Also please do not run this on your personal computer it will clobber your firewall rules. It is meant to be run on an isolated vps/cloud instance.
#### Credits to inchenzo & BasRaayman.
