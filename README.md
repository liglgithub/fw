requirements
	iptables
	ip6tables if need be 

fw app:
	fw is short for the firewall, a lightweight, high-performance simple linux firewall base on netfiler and ip*tables
	it provides fwcmd app to add ip*tables rules,it also provides an app fwcli to control fw.

	Features:
	lightweight
	high-performance
	Thread safe
	Lock-Free Programming
	Logging fw 
	Free and open source
	IPV6 support
	Allowed dynamically add firewall rule 
	Allowed reload rules from xml file
	Allowed reload rules from database
	Allowed dynamically set fw log level
	Allowed packets information with logging to database feature

	Performance:	 
	small overhead

fwcmd app:
	fwcmd add/del/list ip*tables rules to fw
	usage example:
	./fwcmd -h
	./fwcmd -6 -L INPUT
	./fwcmd -I INPUT -p tcp -s 193.168.11.10/24 -j ACCEPT -l
	./fwcmd -A INPUT -p tcp -s 193.168.12.20-193.168.12.30 -j DROP
	./fwcmd -D INPUT INPUT -p tcp -s 193.168.12.20-193.168.12.30 -j DROP
	./fwcmd -L INPUT
	./fwcmd -F INPUT


fwcli app:
	fwcli is config client for fw,you can do following:	
	Set fw log level
	Reload firewall rule from xml file
	Reload firewall rule from database	
	Exit the  firewall

Links
	https://github.com/liglgithub/fw.git
	git@github.com:liglgithub/fw.git
