#Created by: Nicolas Sempere

require 'packetfu'

def scanCheck(packet)
	flags = packet.tcp_flags
	if flags.all? {|flag| flag == 0}
		puts "ALERT: NULL scan is detected"
	elsif flags.urg == 0 and flags.ack == 0 and 
	      flags.psh == 0 and flags.rst == 0 and
	      flags.fin == 1
		puts "ALERT: FIN scan is detected"	
	elsif flags.urg == 1 and flags.ack == 0 and 
	      flags.psh == 1 and flags.rst == 0 and
	      flags.fin == 1
		puts "ALERT: XMAS scan is detected"
	 
	end
end
def liveStreamDetector(packetArray)
	packetArray.stream.each do |raw|
		packet = PacketFu::Packet.parse(raw)
		if packet.is_tcp?
			#flags = packet.tcp_flags
			puts packet.tcp_flags
			scanCheck(packet)		
		elsif packet.is_a?(PacketFu::IPPacket)
			puts "still exciting"
		end 
	end
end


#What sort of object am I expecting to come in?
def reviewLog(array)
	File.each_line do |line|
		case line
			when line.match(/\x4E\x6D\x61\x70/)
				puts "ALERT: Nmap scan detected from"
			when line.match(/\x4E\x69\x6B\x74\x6F/)
				puts "ALERT: Nikto scan detected from"
			when line.match(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) or
			     line.match(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) or
			     line.match(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/)
				puts "ALERT: Credit card leaked in the clear!
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


