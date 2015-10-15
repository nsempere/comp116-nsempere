Created by: Nicolas Sempere
Date created: 13 October 2015


Overall, I spent approximately ten hours implementing this tool.


My implementation of the incident alarm scans for NULL, XMAS,
FIN, and credit card leaks in a live capture. It also parses server logs 
for nmap and nikto scans, attempted phpMyAdmin accesses, and shell code
injections. My understanding of the shellshock vulnerability is that it
applies shell script injections, meaning that my scanning for shellcode in
the server logs acts as a diagnistic for shellshock scanners as well.

The only aspect of the implementation that concerns me is its ability
to scan a live stream for "any nmap scan", nikto scans, and credit card leaks.
I know what to look for (regular expression mapping for either the name of the
scanner or the credit card numbers) and have a general intuition of how to go 
about doing it, but I feel like I haven't accessed the payload of the packets 
correctly. If those scans are not functional, that would be the reason why.

In terms of output, my only concern is that I was not able to
indicate the protocol used in all circumstances. I pull out log information
with regular expressions. That works for IP addresses, which are of a very
specific format, but protocol names follow no such rules. I created an expression
that matches several of the most commonly-used protocol names, but it misses a
few. 


1. Overall, these diagnostic tools earn a grade of "decent" in my opinion. It
certainly handles TCP scans quite well, but probably falls short with the other 
scans and attacks it is meant to address. it feels particularly useless against
shellshock scans and attacks. At the time of diagnosis, the actual alert that an
attacker has injected bash scripts or learned that it is possible is, unfortunately,
useless; the dammage has already been done.

2. With regards to detecting incidents, I would work on connecting related scans.
The average scan will consist of several packets and not just one. As is, however,
this tool treats each packet as a different incident, which is both confusing and 
inaccurate. Any user depending on my service would benefit from seeing those packets
connected.
