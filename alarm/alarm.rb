#Created by: Nicolas Sempere

require 'packetfu'

def scanCheck(packet, count)
	flags = packet.tcp_flags
	puts packet.payload
	if packet.payload.to_s.match(/\x4E\x6D\x61\x70/)
		puts "This was an Nmap scan of some sort or another"
	elsif flags.all? {|flag| flag == 0}
		puts "#{count}. ALERT: NULL scan is detected"
	elsif flags.urg == 0 and flags.ack == 0 and 
	      flags.psh == 0 and flags.rst == 0 and
	      flags.fin == 1
		puts "#{count}. ALERT: FIN scan is detected"	
	elsif flags.urg == 1 and flags.ack == 0 and 
	      flags.psh == 1 and flags.rst == 0 and
	      flags.fin == 1
		puts "#{count}. ALERT: XMAS scan is detected"
	elsif packet.payload.match(/\x4E\x6D\x61\x70/)
		puts "#{count}. ALERT: Nmap scan is detected"
	elsif packet.payload.match(/\x4E\x69\x6B\x74\x6F/)
		puts "#{count}. ALERT: Nikto scan is detected"
	end
end
def liveStreamDetector(packetArray)
	counter = 0
	packetArray.stream.each do |raw|
		counter += 1
		packet = PacketFu::Packet.parse(raw)
		if packet.is_tcp?
			#flags = packet.tcp_flags
			scanCheck(packet, counter)		
		elsif packet.is_a?(PacketFu::IPPacket)
			puts "still exciting"
		end 
	end
end


#What sort of object am I expecting to come in?
def reviewLog(log)
	logNumber = 0
	File.open(log).each do |line|
		logNumber += 1
		if line.match(/\x4E\x6D\x61\x70/)
			puts "#{logNumber}. ALERT: Nmap scan detected from <IP-ADDRESS>"
		elsif line.match(/\x4E\x69\x6B\x74\x6F/)
			puts "#{logNumber}. ALERT: Nikto scan detected from <IP-ADDRESS>"
		elsif (line.match(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) or
		       line.match(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) or
		       line.match(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/))
			puts "#{logNumber}. ALERT: Credit card leaked in the clear from <IP-ADDRESS>"
		elsif line.match("phpMyAdmin")
			puts "#{logNumber}. ALERT: something something phpMyAdmin"
		end
	end
end

def alarm()

	packetStreamArray = PacketFu::Capture.new(
				:start => true, 
				:iface => 'eth0',
				:promisc => true
			)

	if ARGV.length() == 0
		liveStreamDetector(packetStreamArray)
	elsif ARGV[0] == "-r"
		reviewLog(ARGV[1])
	else
		puts "usage:"
		puts "ruby alarm.rb [-r] [<log-file-name>]"
	end
end

alarm()


