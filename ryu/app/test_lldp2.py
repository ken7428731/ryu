from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_5
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.lib.packet import ether_types,lldp,packet,ethernet
from scada_log.write_log_txt import write_log


class MySwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]
    link = []

    def __init__(self, *args,**kwargs):
        super(MySwitch,self).__init__(*args,**kwargs)
        self.mac_to_port = {} # Mac address is defined
        self.write_log_object=write_log()
        self.write_log_object.delete_old_log_file_simple_switch_13()
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures,CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #set if packet is lldp, send to controller
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                          max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,actions=actions)]
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP)
        # //lib/packet/ether_types.py:25:ETH_TYPE_LLDP = 0x88cc
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=1,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)

        self.send_port_desc_stats_request(datapath)# send the request
    

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        mod = parser.OFPFlowMod(datapath=datapath,priority=priority,match=match,instructions=inst)
        datapath.send_msg(mod)


    def send_port_desc_stats_request(self, datapath):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
    
        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)


    # Send the lldp packet
    def send_lldp_packet(self, datapath, port, hw_addr, ttl):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_LLDP,src=hw_addr ,dst=lldp.LLDP_MAC_NEAREST_BRIDGE))

        #chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id=str(datapath.id))
        chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED, chassis_id=str(datapath.id).encode('utf-8'))
        #port_id = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=str(port))
        port_id = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=str(port).encode('utf-8'))
        #port_id = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=b'1/3')
        ttl = lldp.TTL(ttl=1)
        end = lldp.End()
        tlvs = (chassis_id,port_id,ttl,end)
        pkt.add_protocol(lldp.lldp(tlvs))
        pkt.serialize()
        self.logger.info("packet-out %s" % pkt)
        data = pkt.data
        match = ofp_parser.OFPMatch(in_port=ofproto.OFPP_CONTROLLER)
        actions = [ofp_parser.OFPActionOutput(port=port)]
        out = ofp_parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  match=match,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
    '''
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        ports = []
        for p in ev.msg.body:
            if p.port_no <=ofproto.OFPP_MAX: 
                ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                     'state=0x%08x curr=0x%08x advertised=0x%08x '
                     'supported=0x%08x peer=0x%08x curr_speed=%d '
                     'max_speed=%d' %
                     (p.port_no, p.hw_addr,
                      p.name, p.config,
                      p.state, p.curr, p.advertised,
                      p.supported, p.peer, p.curr_speed,
                      p.max_speed))
        self.logger.debug('OFPPortDescStatsReply received: %s', ports)
    '''
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        ports = []
        for stat in ev.msg.body:
            if stat.port_no <=ofproto.OFPP_MAX: 
                ports.append({'port_no':stat.port_no,'hw_addr':stat.hw_addr})
        for no in ports:
            in_port = no['port_no']
            match = ofp_parser.OFPMatch(in_port = in_port)
            for other_no in ports:
                if other_no['port_no'] != in_port:
                    out_port = other_no['port_no']            ###适用于线性结构
            self.logger.debug('port 0x%08x  send lldp  to 0x%08x ', no['port_no'], out_port)
            self.send_lldp_packet(datapath,no['port_no'],no['hw_addr'],10)
            actions = [ofp_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        pkt = packet.Packet(data=msg.data)
        dpid = datapath.id # switch id which send the packetin
        in_port  = msg.match['in_port']

        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_lldp = pkt.get_protocol(lldp.lldp)
        if not pkt_ethernet:
            return 
        #print(pkt_lldp)
        if pkt_lldp:
            self.handle_lldp(dpid,in_port,pkt_lldp.tlvs[0].chassis_id,pkt_lldp.tlvs[1].port_id)


        #self.logger.info("packet-in %s" % (pkt,))

    # Link two switch
    def switch_link(self,s_a,s_b):
        return s_a + '<--->' + s_b
            
    def handle_lldp(self,dpid,in_port,lldp_dpid,lldp_in_port):
        self.write_log_object.write_log_txt_simple_switch_13('-----------------------')
        self.write_log_object.write_log_txt_simple_switch_13('handle_lldp dpid='+str(dpid))
        self.write_log_object.write_log_txt_simple_switch_13('handle_lldp in_port='+str(in_port))
        self.write_log_object.write_log_txt_simple_switch_13('handle_lldp lldp_dpid='+str(int(lldp_dpid)))
        self.write_log_object.write_log_txt_simple_switch_13('handle_lldp lldp_in_port='+str(int(lldp_in_port)))
        self.write_log_object.write_log_txt_simple_switch_13('-----------------------')
        switch_a = 'switch( '+str(dpid)+' ), port'+str(in_port)
        switch_b = 'switch( '+lldp_dpid.decode('utf-8')+' ), port'+lldp_in_port.decode('utf-8')
        link = self.switch_link(switch_a,switch_b)

        # Check the switch link is existed
        if not any(self.switch_link(switch_b,switch_a) == search for search in self.link):
            self.link.append(link)

        print(self.link)