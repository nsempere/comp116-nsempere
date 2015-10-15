#Created by: Nicolas Sempere

require 'packetfu'

def scanCheck(pkt, num)
	flags = pkt.tcp_flags
	if flags.all? {|flag| flag == 0}
		puts "#{num}. ALERT: NULL scan is detected from #{pkt.ip_saddr} (#{pkt.proto.last}) (#{pkt.payload})"
	elsif flags.urg == 0 and flags.ack == 0 and 
	      flags.psh == 0 and flags.rst == 0 and
	      flags.fin == 1
		puts "#{num}. ALERT: FIN scan is detected from #{pkt.ip_saddr} (#{pkt.proto.last}) (#{pkt.payload})"	
	elsif flags.urg == 1 and flags.ack == 0 and 
	      flags.psh == 1 and flags.rst == 0 and
	      flags.fin == 1
		puts "#{num}. ALERT: XMAS scan is detected from #{pkt.ip_saddr} (#{pkt.proto.last}) (#{pkt.payload})"
	elsif pkt.payload.match(/\x4E\x6D\x61\x70/)
		puts "#{num}. ALERT: Nmap scan is detected from  #{pkt.ip_saddr} (#{pkt.proto.last}) (#{pkt.payload})"
	elsif pkt.payload.match(/\x4E\x69\x6B\x74\x6F/)
		puts "#{num}. ALERT: Nikto scan is detected from #{pkt.ip_saddr} (#{pkt.proto.last}) (#{pkt.payload})"
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
	logNum = 0
	rgxIP = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
	rgxProto = "(?:(((T|S)CP)|(S?)(HT|F)?(TP(S?))))"
	File.open(log).each do |line|
		logNum += 1
		if line.match(/\x4E\x6D\x61\x70/)
			puts "#{logNum}. ALERT: Nmap scan is detected from #{line.match(rgxIP)} (#{line.match(rgxProto)}) (#{line})"
		elsif line.match(/\x4E\x69\x6B\x74\x6F/)
			puts "#{logNum}. ALERT: Nikto scan is detected from #{line.match(rgxIP)} (#{line.match(rgxProto)}) (#{line})"
		elsif (line.match(/5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) or
		       line.match(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/) or
		       line.match(/3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/))
			puts "#{logNum}. ALERT: Credit card leaked in the clear from #{line.match(rgxIP)} (#{line.match(rgxProto)}) (#{line})"
		elsif line.match("phpMyAdmin")
			puts "#{logNum}. ALERT: Attemted phpMyAdmin access is detected from #{line.match(rgxIP)} (#{line.match(rgxProto)}) (#{line})"
		elsif line.match(/(\\x[a-zA-Z0-9]{2})+/)
			puts "#{logNum}. ALERT: Attemted shellcode injection is detected from #{line.match(rgxIP)} (#{line.match(rgxProto)}) (#{line})"
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


