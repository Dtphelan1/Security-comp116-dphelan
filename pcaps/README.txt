Assignment 1: 
=============

File 1:
---------

1. How many packets are there in this set?
    A: 861

2. What protocol was used to transfer files from PC to server?
    A: FTP

3. Briefly describe why the protocol used to transfer the files is insecure?
    A: The raw-binary files are transferred over the network, which means if someone is listening to the network being used, the files can be extracted and saved locally -- meaning someone else can copy and save your files mid-transmission.

4. What is the secure alternative to the protocol used to transfer files?
    A: SFTP

5. What is the IP address of the server?
    A: 192.168.1.8

6. What was the username and password used to access the server?
    A: USER: defcon PASS: m1ngisablowhard

7. How many files were transferred from PC to server?
    A: 6

8. What are the names of the files transferred from PC to server?
    A: CDkv69qUsAAq8zN.jpg
       CJoWmoOUkAAAYpx.jpg
       CKBXgmOWcAAtc4u.jpg
       CLu-m0MWoAAgjkr.jpg
       CNsAEaYUYAARuaj.jpg
       COaqQWnU8AAwX3K.jpg

9. Extract all the files that were transferred from PC to server. These files must be part of your submission!
    A: See the rest of the files attached


File 2: 
---------

10. How many packets are there in this set?
    A: 77982

11. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.
    A: 1) larry@radsot.com:Z3lenzmej

12. Briefly describe how you found the username-password pairs.
    A: By searching for frames containing the keyword 'login, LOGIN, USER, PASS, pass, password', and checking see if there was anything sensitive sent over insecure protocols like FTP, IMAP, HTTP, and telnet.

13. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.
    A: IMAP; 87.120.13.118; mail.radsot.com; 143 

IMPORTANT NOTE: PLEASE DO NOT LOG ON TO THE WEBSITE OR SERVICE ASSOCIATED WITH THE USERNAME-PASSWORD THAT YOU FOUND!

14. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfulgranted? Please do not count any anonymous or generic accounts.
    A: larry@radsot.com:Z3lenzmej receives a response containing LOGIN OK, so it seems likely that the pair is legitimate.

File 3:
---------

15. How many plaintext username-password pairs are there in this packet set? Please count any anonymous or generic accounts.
    A:
	1) nab01620@nifty.com:Nifty->takirin1
	2) seymore:butts
	3) jeff:asdasdasd

16. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.
    A:
	1) IMAP; 210.131.4.155; None; 143
	2) HTTP; 162.222.171.208; forum.defcon.org; 80
	3) HTTP; 54.191.109.23; ec2-54-191-109-23.us-west-2.computer.amazonaws.com; 80

IMPORTANT NOTE: PLEASE DO NOT LOG ON TO THE WEBSITE OR SERVICE ASSOCIATED WITH THE USERNAME-PASSWORD THAT YOU FOUND!

17. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted? Please do not count any anonymous or generic accounts.
    A: Two. nab01620@nifty.com:Nifty->takirin1 receives a response containing LOGIN OK, signaing a legitimate pair. jeff:asdasdasd also seems to receive a connection confirmation. seymore:butts on the other hand receives a response containing 403 Forbidden, signaling that the pair was likely invalid. 

18. Provide a listing of all IP addresses with corresponding hosts (hostname + domain name) that are in this PCAP set. Describe your methodology.
    A: See included file ips.txt


General Questions: 
------------------

19. How did you verify the successful username-password pairs?
    Typically I checked to see what the response from the server looked like. If there was something like a HTTP 200 status, or a return message like "Login OK" then I had evidence that the request was successful. 

20. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?
    Use HTTPS instead of HTTP. Encrypt your information before you send it over an network. When you're using things like IMAP and FTP -- don't. Use some of the more secure protocols that have been developed like SFTP. 

