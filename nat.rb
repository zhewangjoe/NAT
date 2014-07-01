class MyController < Controller
	
	Ipv4_addr = Struct.new(:ipv4_saddr, :ipv4_port)

	###################
	# read rule from configuration file
	##################
	def start
		@maps = Hash.new
		@ports = *(50000..60000)
		@ex_ip = "10.10.11.1"
	end

	###################
	#send rule to switch
	#for every pkt that enters the switch, send it to controller
	#let icmp and arp packets pass directly
	###################
	def switch_ready datapath_id
		#allow arp and icmp packets
		dl_type_arp = 0x0806
		dl_type_ipv4 = 0x0800
		dl_type_ipv6 = 0x86dd
		send_flow_mod_add( datapath_id, 
			:match => Match.new( {:dl_type => dl_type_arp } ),
			:actions => ActionOutput.new( OFPP_NORMAL ) 
			)
		send_flow_mod_add( datapath_id, 
			:match => Match.new( {:dl_type => dl_type_ipv4, :nw_proto => 1 } ),
			:actions => ActionOutput.new( OFPP_CONTROLLER ) 
			)
		send_flow_mod_add( datapath_id,
                        :match => Match.new( {:dl_type => dl_type_ipv4, :nw_proto => 6 } ),
                        :actions => ActionOutput.new( OFPP_CONTROLLER )
                        )
		send_flow_mod_add( datapath_id,
                        :match => Match.new( {:dl_type => dl_type_ipv4, :nw_proto => 17 } ),
                        :actions => ActionOutput.new( OFPP_CONTROLLER  )
                        )
		send_flow_mod_add( datapath_id,
                        :match => Match.new( {:dl_type => dl_type_ipv6 } ),
                        :actions => ActionOutput.new( OFPP_NORMAL )
                        )
		puts "rule added to switch for arp and ipv6 pkt: send normally"
	end

	#######################
	# if packet is allowed in the configure file, add a rule to the switch
	# that also allows future packets going through the reverse path
	# else deny it (drop it)
	######################
	def packet_in datapath_id, message
		#puts "msg in"
		#puts "#{message.ipv4_saddr.to_s} to #{message.ipv4_daddr.to_s}"
		src_match = Match.new( :nw_src => "192.168.0.0/24" )
		dst_match = Match.new( :nw_dst => @ex_ip )
		if message.tcp? || message.udp?
			if src_match.compare( ExactMatch.from( message ) )
				#puts "convert src"
				ipv4_addr = Ipv4_addr.new(message.ipv4_saddr.to_s, message.tcp_src_port ? message.tcp_src_port : message.udp_src_port )
				#puts "ipv4_addr"
				#puts ipv4_addr
				if @maps.has_key?( ipv4_addr )
					port = @maps[ ipv4_addr ]
					#puts "port1"
					#puts port
				else
					port = @ports.pop
					#puts "port2"
                                        #puts port
					@maps[ ipv4_addr ] = port
					@maps[ port ] = ipv4_addr
					puts "Created mapping: #{ipv4_addr.ipv4_saddr} #{ipv4_addr.ipv4_port} to #{@ex_ip} #{port}"
				end
				action = [
						SetIpSrcAddr.new( @ex_ip ),
						SetTransportSrcPort.new(port),
						ActionOutput.new( :port => OFPP_FLOOD )
					]
				packet_out datapath_id, message, action
				return
			end
			if dst_match.compare( ExactMatch.from( message ) )
                                #puts "convert dst"
				#puts "message.dst_port"
				dst_port = message.tcp_dst_port ? message.tcp_dst_port : message.udp_dst_port
				#puts dst_port
				if @maps[ dst_port ]
					ipv4_addr =  @maps[ dst_port ]
					#puts "ipv4_addr"
					#puts ipv4_addr
				else
					puts "Dropping msg as dst is not understood"
					return
				end
				action = [
						SetIpDstAddr.new( ipv4_addr.ipv4_saddr ),
						SetTransportDstPort.new( ipv4_addr.ipv4_port ),
                                                ActionOutput.new( :port => OFPP_FLOOD )
                                        ]
				packet_out datapath_id, message, action
				return
                        end	
		else
			#puts "Other msg"
			#puts message.icmpv4?
			if src_match.compare( ExactMatch.from( message ) )
                                #puts "convert src"
                                icmpv4_id = message.icmpv4_id
                                #puts "icmpv4_id"
                                #puts icmpv4_id
                                if !@maps.has_key?( icmpv4_id )
                                        @maps[ icmpv4_id ] = message.ipv4_saddr.to_s
                                end
                                action = [
                                                SetIpSrcAddr.new( @ex_ip ),
                                                ActionOutput.new( :port => OFPP_FLOOD )
                                        ]
                                packet_out datapath_id, message, action
                                return
                        end
                        if dst_match.compare( ExactMatch.from( message ) )
                                #puts "convert dst"
                                icmpv4_id = message.icmpv4_id
                                #puts "icmpv4_id"
                                #puts icmpv4_id
				if @maps[ icmpv4_id ]
                                        ipv4_addr =  @maps[ icmpv4_id ]
                                        #puts "ipv4_addr"
                                        #puts ipv4_addr
                                else
					puts "Dropping msg as dst is not understood"
                                	return
				end
                                action = [
                                                SetIpDstAddr.new( ipv4_addr ),
                                                ActionOutput.new( :port => OFPP_FLOOD )
                                        ]
                                packet_out datapath_id, message, action
                                return
                        end
		end

		packet_out datapath_id, message, ActionOutput.new( :port => OFPP_FLOOD )
	end

	def packet_out(datapath_id, message, action)
    		send_packet_out(
      			datapath_id,
      			:in_port => message.in_port,
			:buffer_id => 0xffffffff,
			:data => message.data,
      			:actions => action
    		)
	end
	
end
