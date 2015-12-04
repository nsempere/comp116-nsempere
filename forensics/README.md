Michael Seltzer and Nick Sempere
Comp 116: Security
Assignment 5: Forensics

Part A

	Images a.jpg, b.jpg, and c.jpg appear to be the same in terms of image quality and coloration. However the size of the files differs as a is 2.1MB while both B and C are 2.2. Using the command tool application diff, it appears a is different from both b and c, but b and c are the exact same file. Furthermore a.jpg does not have metadata, while b and c shows the metadata listed in "meta.png".

	This metadata was extracted via a web tool called metapicz.com.

Part B

1. What is/are the disk format(s) of the disk on the suspect's computing device?

The following two partitions were found on the disk image provided:
Win95 FAT16
Linux ext

2. Is there a phone carrier involved?

	In the /var/log/daemon.log, the network devices are enumerated and a switch to detect WiMAX is enabled. This is shown in the lines below:
	Oct  7 16:17:21 kali NetworkManager[343]: <info> WiMAX enabled by radio killswitch; enabled by state file
	Oct  7 16:17:21 kali NetworkManager[343]: <info> Networking is enabled by state file
	Oct  7 16:17:21 kali NetworkManager[343]: <info> (lo): link connected
	Oct  7 16:17:21 kali NetworkManager[343]: <info> (lo): carrier is ON
	Oct  7 16:17:21 kali NetworkManager[343]: <info> (lo): new Generic device (driver: 'unknown' ifindex: 1)

 In addition there is a WiFi device (based on the driver version shown below it may be this device: http://www.amazon.com/TP-LINK-TL-WN725N-Wireless-Adapter-150Mbps/dp/B008IFXQFU). The driver and information is shown below:

	Oct  7 16:17:21 kali NetworkManager[343]: <info> (eth0): new Ethernet device (driver: 'smsc95xx' ifindex: 2)


3. What operating system, including version number, is being used? Please elaborate how you determined this information.

The operating system is Kali Debian as shown by the auth.log file in var/log/auth.log. The version number is Linux 3.16.0-4-armmp-lpae armv7l Debian as shown in /2/var/log/Xorg.0.log.

4. What applications are installed on the disk? Please elaborate how you determined this information.

The disk came with all of the applications and tools that would normally exist on a Kali system. The following applications were installed with apt and were found using the history log in /var/log/apt/history.log:

libgssapi-krb5-2:armhf (1.12.1+dfsg-19, 1.12.1+dfsg-19+deb8u1), php5-gd:armhf (5.6.13+dfsg-0+deb8u1, 5.6.14+dfsg-0+deb8u1), libgdk-pixbuf2.0-0:armhf (2.31.1-2+deb8u2, 2.31.1-2+deb8u3), libkrb5-3:armhf (1.12.1+dfsg-19, 1.12.1+dfsg-19+deb8u1), krb5-locales:armhf (1.12.1+dfsg-19, 1.12.1+dfsg-19+deb8u1), libk5crypto3:armhf (1.12.1+dfsg-19, 1.12.1+dfsg-19+deb8u1), libapache2-mod-php5:armhf (5.6.13+dfsg-0+deb8u1, 5.6.14+dfsg-0+deb8u1), kali-root-login:armhf (1.1, 1.2), set:armhf (6.5.6-0kali1, 6.5.8-0kali1), libpng12-0:armhf (1.2.50-2+b2, 1.2.50-2+deb8u1), ntpdate:armhf (4.2.6.p5+dfsg-7, 4.2.6.p5+dfsg-7+deb8u1), postgresql-9.4:armhf (9.4.3-0+deb8u1, 9.4.5-0+deb8u1), php5-readline:armhf (5.6.13+dfsg-0+deb8u1, 5.6.14+dfsg-0+deb8u1), php5-curl:armhf (5.6.13+dfsg-0+deb8u1, 5.6.14+dfsg-0+deb8u1), libkrb5support0:armhf (1.12.1+dfsg-19, 1.12.1+dfsg-19+deb8u1), nmap:armhf (6.49~BETA5-0kali1~r1u1, 7.00-0kali1~r1u1), kali-desktop-common:armhf (2.41, 2.42), kali-desktop-xfce:armhf (2.41, 2.42), libpq5:armhf (9.4.3-0+deb8u1, 9.4.5-0+deb8u1), mysql-common:armhf (5.5.44-0+deb8u1, 5.5.46-0+deb8u1), libgdk-pixbuf2.0-common:armhf (2.31.1-2+deb8u2, 2.31.1-2+deb8u3), libmysqlclient18:armhf (5.5.44-0+deb8u1, 5.5.46-0+deb8u1), metasploit-framework:armhf (4.11.4-2015090201-0kali1, 4.11.5-2015103001-0kali1), php5-mysql:armhf (5.6.13+dfsg-0+deb8u1, 5.6.14+dfsg-0+deb8u1), postgresql-client-9.4:armhf (9.4.3-0+deb8u1, 9.4.5-0+deb8u1), libfreetype6:armhf (2.5.2-3, 2.5.2-3+deb8u1), php5-common:armhf (5.6.13+dfsg-0+deb8u1, 5.6.14+dfsg-0+deb8u1), php5-cli:armhf (5.6.13+dfsg-0+deb8u1, 5.6.14+dfsg-0+deb8u1), wpasupplicant:armhf (2.3-1+deb8u1, 2.3-1+deb8u3), ndiff:armhf (6.49~BETA5-0kali1~r1u1, 7.00-0kali1~r1u1)

5. Is there a root password? If so, what is it?

The root password on this system is “raspberry”, which happens to be the default password for the device in question (raspberrypi). We determined the password by using John the Ripper with a wordlist called “rockyou.txt” to  crack the passwords listed in /etc/shadow.

6. Are there any additional user accounts on the system? If so, what are their passwords?

There are two other user accounts, which are listed below:
	“blinkythewonderchimp” (password: “football”)
	“defcon” (password: “wolverine”)

We were able to decypher these passwords by using the John the Ripper (a default crack) to brute-force the remaining passwords. 

7. List some of the incriminating evidence that you found. Please elaborate where did you find the evidence, and how you uncovered the evidence.

We found several photographs on the disk, as well as three videos of various horse races. In addition there was a bash history file where the root user used shred in order to securely delete files. The following lines show the activity:
shred -n 30 -r config.php
shred -n 30 -u config.php


8. Did the suspect move or try to delete any files before his arrest? Please list the name(s) of the file(s) and any indications of their contents that you can find.

The suspect deleted four pictures (ap7-10.jpg) around at around the same time on 2015-11-21 21:30:22. This is shown using the tool Autopsy in order to view metadata related to the deleted files. In addition, there were files deleted by the root user shown in the bash command history log. The relevant pieces of history are:
		shred -n 30 -r config.php
		shred -n 30 -u config.php


9. Did the suspect save pictures of the celebrity? If so, how many pictures of the celebrity did you find? (including any deleted images)

	It appears that there around 10 pictures of the celebrity within the disk which are all located within the folder /home/blinkythewonderchip/documents. 

10. Are there any encrypted files? If so, list the contents in the encrypted file and provide a brief description of how you decrypted the file.

Encrypted files were found on the user’s device within the ext partition within /home/blinkythewonderchip/documents/profile.zip. The file was encrypted with the password “American” which was found by performing a dictionary based attacked (using the RockYou password leak). Inside the password protected zip file, the image that was found is stored in this repo as "evidence.jpg"

10. Who is the celebrity that the suspect has been stalking?

This suspect has been stalking American Pharoah, the racehorse.
