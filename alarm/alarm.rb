####################
# By: Dylan Phelan 
# On: 10/13/2015
#
# Purpose: To provide a background check on traffic
#          through a particular network interface and to
#          signal an alarm if any suspicious activity is seen
#

require 'packetfu'
require 'apachelogregex' 

$incidentNum = 0

# Checks to see if no flags are set on a packet's flags
def isNull(flags)  
    return flags.to_i() == 0
end


# Checks to see if fin flag is set on a packet's flags
def isFin(flags) 
    return flags.to_i() == 1
end


# Checks to see if xmas flags -- arg, fin and urg, are set, rest off.
def isXMAS(flags) 
    return (flags.fin == 1 && flags.psh == 1 && flags.urg == 1 && 
            flags.ack == 0 && flags.syn == 0 && flags.rst == 0)
end   


# Checks to see if a payload implies that a Nikto scan is being done 
#   by checking for the word "nikto" in the payload. Checks hex of nikto also
def isNikto(payload) 
    return payload.scan(/(nikto) | (\x6e\x69\x6b\x74\x6f)/i).length > 0
end


# Checks to see if a payload implies that a nmap scan is being done 
#   by checking for the words "nmap" in payload. Checks for hex of nmap also
def isNmap(payload) 
    return payload.scan(/(nmap) | (\x6e\x6d\x61\x70)/i).length > 0
end


# Checks to see if plaintext credit card info is being sent
def containsCreditCard(payload) 
    #use regex to check against provided credit card regex -- 
    #courtesy of http://www.sans.org/security-resources/idfaq/snort-detect-credit-card-numbers.php
  
    visa = payload.scan(/4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/i)
    disc = payload.scan(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/i)
    mast = payload.scan(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/i)
    amer = payload.scan(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/i)
    return ((visa.length + disc.length + mast.length + amer.length) > 0)
end 


# Prints out the alarm according to pre-specified format
def soundAlarm (incidentNum, descrip, packet)
    puts "#{incidentNum}. ALERT: #{descrip} is detected from #{packet.ip_saddr} (#{packet.proto.last}) (#{packet.payload})!"
end


# runs all the scan checks in sequence
def trafficCheck(packet)
    if (isNull(packet.tcp_flags))
	$incidentNum += 1
	soundAlarm($incidentNum, "NULL SCAN", packet);
    end 
    if (isFin(packet.tcp_flags))
	$incidentNum += 1
	soundAlarm($incidentNum, "FIN SCAN", packet);
    end 
    if (isXMAS(packet.tcp_flags))
	$incidentNum += 1
	soundAlarm($incidentNum, "XMAS SCAN", packet);
    end 
    if (isNikto(packet.payload))
	$incidentNum += 1
	soundAlarm($incidentNum, "NIKTO SCAN", packet);
    end 
    if (isNmap(packet.payload))
	$incidentNum += 1
	soundAlarm($incidentNum, "NMAP SCAN", packet);
    end 
    if (containsCreditCard(packet.tcp_header.body)) 
	$incidentNum += 1
	soundAlarm($incidentNum, "Credit card being sent", packet)
    end 
end

    
# Sniffs current traffic for packets worth noting
def sniff()
    traffic = PacketFu::Capture.new(:start => true, :iface => 'eth0', :promisc => true)
    traffic.stream.each do |binary| 
	packet = PacketFu::Packet.parse(binary)
	if (packet.class == PacketFu::TCPPacket)
	    trafficCheck(packet);
	end 
    end
end


# Sounds the alarm in the case of log file
def soundLogAlarm(incidentNum, descrip, srcAddr, protocol, payload)
    puts "#{incidentNum}. ALERT: #{descrip} is detected from #{srcAddr} (#{protocol}) (#{payload})!"
end
  
# Determines if line from log include phpmyAdmin 
def isPhp(l)
    return l.scan(/phpMyAdmin/i).length > 0
end

# Determines if a line from log file includes 'masscan' in request
def isMassscan(l) 
    return l.scan(/masscan/i).length > 0
end

# Determines if a line from log file includes shell code, by 
#   searching for multiple raw hex values
def isShellcode(l) 
    return l.scan(/\\x..\\x../).length > 0
end

# Determines if a line from log file includes something that 
#   seems to be searching for the shell shock vulnerability by 
#   looking to see if logs include any of the following interesting key words
def isShellshock(l)
    return l.scan(/(='\(\))|(env\sX=)|(<<EOF)|(x\(\) { _;};)|(:";)/i).length > 0
end
    
# For a line from a log file, check it for possible problems
def logCheck(l)
    format = '%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'
    parser = ApacheLogRegex.new(format)
    
    elements = parser.parse(l);
    addr     = elements["%h"]
    protocol = elements["%r"].split(" ")[2]
    payload  = elements["%r"]    
    
    if (isNmap(l)) 
	$incidentNum += 1
	soundLogAlarm($incidentNum, "NMAP SCAN", addr, protocol, payload)
    end 
    if (isNikto(l)) 
	$incidentNum += 1 
	soundLogAlarm($incidentNum, "NIKTO SCAN", addr, protocol, payload)
    end 
    if (isPhp(l))
	$incidentNum += 1
	soundLogAlarm($incidentNum, "PHPMyAdmin FOUND", addr, protocol, payload)
    end 
    if (isShellcode(l))
	$incidentNum += 1
	soundLogAlarm($incidentNum, "SHELL CODE FOUND", addr, protocol, payload)
    end  
    if (isShellshock(l))
	$incidentNum += 1 
	soundLogAlarm($incidentNum, "SHELL SHOCK CODE FOUND", addr, protocol, payload)
    end
    if (isMassscan(l))
	$incidentNum += 1
	soundLogAlarm($incidentNum, "MASSCAN FOUND", addr, protocol, payload)
    end
end

# Parses a log file for details worth noting
def parseLog(file)
    file.each_line do |l|
	 logCheck(l)
    end
end

#############
# Main

if (ARGV[0])
    if (ARGV[0] != "-r")
	puts "Incorrect format: Accepts only 'ruby alarm.rb' or 'ruby alarm.rb -r <logfile>'"
    else
	if (ARGV[1])
	  file = File.open(ARGV[1], "r")
	  parseLog(file)
	  file.close()
	elsif 
	  puts "Incorrect format: Accepts only 'ruby alarm.rb' or 'ruby alarm.rb -r <logfile>'"
	end 
    end 
else 
    sniff()
end
