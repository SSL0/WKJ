# WKJ
WIFI Killer/Jammer

I made this script for sporting interests. So **USE FOR INFORMATIONAL PURPOSES ONLY!**
<hr>

# How dose it work?(Killer)

Your device sends an ARP packet to the victim/victims on behalf of the network gateway, but instead of the correct MAC address, it indicates a fake one. The ARP table on the victim's device will change to a fake MAC address. Since Ethernet and wifi use MAC addresses to communicate, therefore, the victim will not have access to the Internet

P.S Perhaps you can use this on Ethernet networks(I don't test it).

# Dependencies
* Scapy `pip3 install scapy`
# TODO:
- [ ] Add name of devices
- [ ] Start work on Jammer
