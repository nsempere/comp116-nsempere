Created by: Nicolas Sempere
Date created: 13 October 2015


Overall, I spent approximately ten hours implementing this tool.


	My implementation of the incident alarm scans for NULL, XMAS,
FIN, and credit card leaks in a live capture. It also parses server logs 
for nmap and nikto scans, attempted phpMyAdmin accesses, and shell code
injections. My understanding of the shellshock vulnerability is that it
applies shell script injections, meaning that my scanning for shellcode in
the server logs acts as a diagnistic for shellshock scanners as well.


	In terms of output, my only concern is that I was not able to
indicate the protocol used in all circumstances. I pull out log information
with regular expressions. That works for IP addresses, which are of a very
specific format, but protocol names follow no such rules. I created an expression
that matches several of the most commonly-used protocol names, but it misses a
few. 

