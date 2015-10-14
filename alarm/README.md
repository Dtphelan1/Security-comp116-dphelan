
# README
## Alarm.rb -- By Dylan Phelan -- On 10/13/2015

### Implemented
- The author believes that all aspects of the assignment have been properly addressed. 
  That includes analyzing network traffic for NULL scans, FIN scans, XMAS scans, nmap scans,
  Nikto scans and credit card leaks, as well as analyzing server logs for nmap scans, nikto
  scans, masscan, shellshock exploits, shellcode exploits, and anything relating to phpMyAdmin.
- Collaborators for this assignment include: Nitesh Gupta.
- Approximately 8 hours were spent completing this assignment.


### Heuristics
Several heuristics were used in this assignments to "determine" if particular events occur:
1. Nmap scans are identified by searching the packet.payload for the word "nmap" or its hex equivalent.
2. Nikto scans are identified in the identical way. 
3. Credit cards are limited to Visa, American Express, Discover and Mastercard.
4. Shellshock exploits are determined by matching "somewhat" unique expressions found in the most common 
   uses of the shellshock exploit, as offered at: https://shellshocker.net/
5. Masscan is determined by checking a line of a log file for the word "masscan"
6. The use of phpMyAdmin is determined by, with case insensitivity, searching a line of a log file for "phpMyAdmin"
7. Shellcode is determined by simply searching for more than one hex value in the line of the log file.


### Moving Forward
If more time was allotted for this assignment, future expansions could include: 
- More creditcard options for the credit card leak.
- Nmap, nikto and masscan can all have more robust searching schemes, including: 
  - In the case of nmap and nikto, searching through more than just the packet.payload
  - In the case of all three, searching for search-specific signatures, like flags set, header information, common payload information, etc...
- Searching for attempts at XSS.
- Searching for SQL injections.
- And more....