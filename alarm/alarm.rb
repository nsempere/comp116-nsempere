#Created by: Nicolas Sempere

require 'packetfu'

def liveStreamDetector(packetArray)
	packetArray.stream.each do |raw|
		packet = PacketFu::Packet.parse(raw)
		if packet.is_a?(PacketFu::TCPPacket)
			puts "woohooooooo"
		elsif packet.is_a?(PacketFu::IPPacket)
			puts "still exciting"
		end 
	end
end


#What sort of object am I expecting to come in?
def reviewLog(array)
	puts File.open(array)
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


