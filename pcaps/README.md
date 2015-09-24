Ncolas Sempere
22 September 2015

				Packet Sleuth

set1.pcap

	1. There are 861 packets in this set.
	2. In the case, the files were transfered vi FTP (File Transfer Protocol).
	3. FTP is an insecure protocol because it stores and transmits usernames and
	   passwords in plain text. Any sniffer (myself included) can easily intercept
	   the packets used to send the data and read that username and password very
	   easily.
	4. A more secure alternative of FTP would be SFTP, which fulfills the same role 
	   while encrypting sensitive information like passwords.
	5. The server can be identified as the machine that is sending responses in this
	   packet capture. Its IP address is 192.168.1.8  
	6. Username: defcon 
	   Password: m1ngisablowhard
	7. A total of six files were transfered to the server.
	8. The names of the transferred files are as follows:
		
		- CDkv69qUsAAq8zN.jpg
		- CJoWmoOUkAAAYpx.jpg
		- CKBXgmOWcAAtc4u.jpg
		- CLu-mOMWoAAgjkr.jpg
		- CNsAEaYUYAARuaj.jpg
		- COaqQWnU8AAwX3K.jpg
	   
	   On another pretty funny note, I was able to sniff out some computer that made a
	   request for an "adult" website. Reading through that HTML was pretty bad.  
	9. See attached files

set2.pcap

	10. There are a total of 77982 packets in this capture
	11. I was able to find a total of seven username/password combinations.
	12. By looking up all the ports that transfered information in plain text, I was able to 
	    filter through the capture looking for streams using each of those protocols. I looked 
	    through the available streams from each port for usernames and passwords in plain text.
	    That, however, only revealed one username/password pair. To find the rest, I had to 
	    use ettercap, first running the pcap file through ettercap and then running "etterlog"
	    witht the -p flag, which searches specifically for login credentials.
	13. The single genuine username/password combination I found was used under the IMAP 
	    protocol, which is used predominately for emails. 87.120.13.118 --> mail.radslot.com. 
	    Additionally, the user was making an amazon purchase. 
	14. Only one of the plaintext login credentials were legitimate.

set3.pcap

	15. In this packet set, there are a total of thirteen username/password combinations,
	    inclusive of generics and anonymous logins.
	16. 
		- IP: 10.0.8.253 PORT: 161 Protocol: SNMP
		- IP: 10.0.8.254 PORT: 161 Protocol: SNMP 
		- IP: 10.5.10.10 PORT: 161 Protocol: SNMP 
		- IP: 10.26.0.147 PORT: 161 Protocol: SNMP 
		- IP: 54.191.109.23 PORT: 80 Protocol: HTTP ec2-54-191-109-23.us-west-2.compute.amazonaws.com
		  * Cool, an AWS server that someone was trying to hit.
		- IP: 162.222.171.208 PORT: 80 Protocol: HTTP Domain: forum.defcon.org
		- IP: 172.16.15.31 PORT: 161 Protocol: SNMP 
		- IP: 192.168.1.3 PORT: 161  Protocol: SNMP (Two logins from same device)
		- IP: 192.168.1.11 PORT: 161 Protocol: SNMP 
		- IP: 192.168.1.200 PORT: 161 Protocol: SNMP 
		- IP: 192.168.15.12 PORT: 161 Protocol: SNMP 
		- IP: 210.131.4.155 PORT 143 Protocol: IMAP 

	    I had trouble finding the domains for most of these IP addresses. I attempted to determine
	    the domains using both nslookup and the address resolution tool in wireshark.
	17. Of the three non-generic/anonymous logins I found, only one was legitimate.
	18. See included markdown file IP_Domain.md for a full table. I obtained this table by using 
	    the address resolution tool supported by wireshark.
	19. I was able to verify whether or not a username/password pair was successful or not by
	    examining the TCP streams for those interaction. The IMAP login indicated a successful
	    login in plain text, while I was able to confirm that the two HTTP logins were invalid
	     by noticing the 403 error codes (Forbidden/Unauthorized) that returned.
	20. I would encourage these people to use more secure counterparts to the respective
	    protocols they were using in this instance. HTTPS for instance, is extremely similar
	    to HTTP apart from the encoding it does.
