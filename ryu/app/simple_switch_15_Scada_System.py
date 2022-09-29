
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -*- coding: utf-8 -*-
#  可讓使用中文註解
#--------參考網址-------------------------#
# https://stackoverflow.com/questions/49971882/delete-flows-matching-specific-cookie-openflow-1-3-5-spec-support-by-openvswit
# https://gist.github.com/aweimeow/d3662485aa224d298e671853aadb2d0f 的基本教學

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from scada_log.write_log_txt import write_log
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp,udp
from SCADA_Device_Information.Load_SCADA_Information_Data import Load_Data
import threading

RULE_1_TABLE=1
RULE_2_TABLE=2
RULE_3_TABLE=3
RULE_4_TABLE=4
RULE_5_TABLE=5
RULE_6_TABLE=6
SCADA_Information_List=[]

def Load_SCADA_Information(): #讀取Device_Information.json資訊
    global SCADA_Information_List
    Load_SCADA_Information_Object=Load_Data()
    while True:
        SCADA_Information_List=Load_SCADA_Information_Object.Load_Information()
        # print('SCADA_Information_List='+str(SCADA_Information_List))


class SimpleSwitch15(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch15, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        self.write_log_object=write_log()
        self.write_log_object.delete_old_log_file()

        # self.load_Scada_thread=[]
        thread=threading.Thread(target=Load_SCADA_Information) #一直讀取 Device_Information.json，如果有做更改並在全域提醒
        thread.start()
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # 一開始 Switch 連上 Controller 時的初始設定 Function
        datapath = ev.msg.datapath # 接收 OpenFlow 交換器實例
        ofproto = datapath.ofproto  # OpenFlow 交換器使用的 OF 協定版本
        parser = datapath.ofproto_parser # 處理 OF 協定的 parser

        #--------新增一筆所有封包當阻擋的flow -------------#
        start_default_match = parser.OFPMatch()
        start_default_actions=[]
        self.add_flow(datapath,0,65535,start_default_match,0,start_default_actions)
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.

        # 首先新增一個空的 match，也就是能夠 match 任何封包的 match rule
        match = parser.OFPMatch()
        # 指定這一條 Table-Miss FlowEntry 的對應行為
        # 把所有不知道如何處理的封包都送到 Controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # 把 Table-Miss FlowEntry 設定至 Switch，並指定優先權為 0 (最低)
        self.add_flow(datapath,0, 0, match,0, actions)

        # #------測試(如果比對到tcp且是請求連線的訊號封包時，就丟掉)------------------#
        # self.table_id=0
        # self.priority=666
        # self.importance = 0
        # # match = parser.OFPMatch(in_port=1)
        # # match_1 = parser.OFPMatch(eth_type=0x0800,ipv4_src="192.168.3.40")#只比對ip
        # match_1 = parser.OFPMatch(eth_type=0x0800,ipv4_dst="192.168.3.40",ip_proto=0x6,tcp_dst=0x1f6,tcp_flags=0x2)#比對ip,tcp,tcp的flags
        
        # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                   ofproto.OFPCML_NO_BUFFER)]                                      
        # self.add_flow(datapath,0, self.priority, match_1, 0, actions)

        #-------測試2 (測試Table 0 比對到的封包後再到Table 1進行比對[table 1 為如果是TCP 封包的話，就丟棄])-----------------#
        table_0_match_1 = parser.OFPMatch(eth_type=0x0800,ipv4_src="192.168.3.40")#比對封包ip 往PLC的
        table_0_match_2 = parser.OFPMatch(eth_type=0x0800,ipv4_dst="192.168.3.40")#比對ip往PLC的
        table_0_inst_rule_1= [parser.OFPInstructionGotoTable(RULE_1_TABLE)] #Go to The Table 1
        self.add_flow(datapath,0, 10, table_0_match_1, table_0_inst_rule_1) #在table 0比對到 往table 1送
        self.add_flow(datapath,0, 10, table_0_match_2, table_0_inst_rule_1) #在table 0比對到 往table 1送

        table_1_match_1 = parser.OFPMatch(eth_type=0x0800,ip_proto=0x6)#如果是TCP的話
        table_1_actions_1 = []                                      
        self.add_flow(datapath,RULE_1_TABLE, 2, table_1_match_1,0,table_1_actions_1) #在table 0比對到 往table 1送
        
        table_1_match_0 = parser.OFPMatch() #Table_1如果都沒有 match的話就送往Controller
        table_1_actions_0 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath,RULE_1_TABLE, 0, table_1_match_0,0, table_1_actions_0)
        
        #移除 一開始新增的 所有封包當阻擋的flow
        match = parser.OFPMatch()
        self.delete_flow(datapath,0,65535,match,0)



    def add_flow(self, datapath,table_id, priority, match, inst=0, actions=None):
        # 取得與 Switch 使用的 IF 版本 對應的 OF 協定及 parser
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Instruction 是定義當封包滿足 match 時，所要執行的動作
        # 因此把 action 以 OFPInstructionActions 包裝起來
        if inst==0:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        else:
            inst=inst
        # FlowMod Function 可以讓我們對 Switch 寫入由我們所定義的 Flow Entry
        mod = parser.OFPFlowMod(cookie=0x01,datapath=datapath, table_id=table_id,priority=priority,command=ofproto.OFPFC_ADD,
                                match=match, instructions=inst)
        print('add_flow='+str(mod))
        datapath.send_msg(mod)# 把定義好的 FlowEntry 送給 Switch
    def delete_flow(self,datapath,table_id, priority, match, inst=0, actions=None): #刪除Flow (可以查看[1]的參考網址)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # if inst==0:
        #     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
        #                                          actions)]
        # else:
        #     inst=inst

        # 刪除FLOW 。 ofproto.OFPFC_DELETE_STRICT 為匹配(match與priority)到規則後，進行刪除
        mod=parser.OFPFlowMod(cookie=0x01,datapath=datapath, table_id=table_id,command=ofproto.OFPFC_DELETE_STRICT,
                              out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY,
                              priority=priority,match=match)
        result=datapath.send_msg(mod)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        # self.write_log_object.write_log_txt("ev.msg="+str(msg))
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        # ------- 測試 ---------------------------#

        if pkt.get_protocols(ipv4.ipv4):
            self.ipv4=pkt.get_protocols(ipv4.ipv4)[0]
            self.ipv4_src = self.ipv4.src
            self.ipv4_dst = self.ipv4.dst
            self.ipv4_protocol=self.ipv4.proto
            self.ipv4_services=self.ipv4.tos
        if pkt.get_protocols(tcp.tcp):
            self.tcp=pkt.get_protocols(tcp.tcp)[0]
            self.tcp_src_port=self.tcp.src_port
            self.tcp_dst_port=self.tcp.dst_port
            self.tcp_seq_number=self.tcp.seq
            self.tcp_ack=self.tcp.ack
            self.tcp_flags=self.tcp.bits

        if pkt.get_protocols(ipv4.ipv4):
            print("ipv4_src="+str(self.ipv4_src))
            print("ipv4_dst="+str(self.ipv4_dst))
        if pkt.get_protocols(tcp.tcp):
            print("tcp="+str(self.tcp))
            print("tcp_seq_number="+str(self.tcp_seq_number))

        #將資料寫到log檔
        if pkt.get_protocols(tcp.tcp):
            self.write_log_object.write_log_txt("-----------------")
            self.write_log_object.write_log_txt("ev="+str(ev))
            self.write_log_object.write_log_txt("ev.msg="+str(msg))
            # self.write_log_object.write_log_txt("packet_timestamp="+str(self.packet_timestamp))
            # self.write_log_object.write_log_txt("packet_datetime="+str(self.packet_datetime))
            # self.write_log_object.write_log_txt("ev.msg.data="+str(self.data))
            self.write_log_object.write_log_txt("datapath="+str(datapath))
            self.write_log_object.write_log_txt("parser="+str(parser))
            self.write_log_object.write_log_txt("in_port="+str(in_port))
            self.write_log_object.write_log_txt("pkt="+str(pkt))
            # self.write_log_object.write_log_txt("pkt_len="+str(self.pkt.__len__()))
            self.write_log_object.write_log_txt("eth="+str(eth))
            self.write_log_object.write_log_txt("eth_dst="+str(dst))
            self.write_log_object.write_log_txt("eth_src="+str(src))
            # if self.pkt.get_protocols(ipv4.ipv4):
            self.write_log_object.write_log_txt("ipv4="+str(self.ipv4))
            self.write_log_object.write_log_txt("ipv4.src="+str(self.ipv4_src))
            self.write_log_object.write_log_txt("ipv4.dst="+str(self.ipv4_dst))
            # if self.pkt.get_protocols(tcp.tcp):
            self.write_log_object.write_log_txt("tcp="+str(self.tcp))
            self.write_log_object.write_log_txt("tcp_src_port="+str(self.tcp_src_port))
            self.write_log_object.write_log_txt("tcp_dst_port="+str(self.tcp_dst_port))
            self.write_log_object.write_log_txt("tcp_seq_number="+str(self.tcp_seq_number))







        # -------- END ------------------------#
        dpid = datapath.id # Switch 的 datapath id (獨一無二的 ID)

        # 如果 MAC 表內不曾儲存過這個 Switch 的 MAC，則幫他新增一個預設值
        # ex. mac_to_port = {'1': {'AA:BB:CC:DD:EE:FF': 2}}
        #     但是目前 dpid 為 2 不存在，執行後 mac_to_port 會變成
        #     mac_to_port = {'1': {'AA:BB:CC:DD:EE:FF': 2}, '2': {}}
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        # 我們擁有來源端 MAC 與 in_port 了，因此可以學習到 src MAC 要往 in_port 送
        self.mac_to_port[dpid][src] = in_port

        # 如果 目的端 MAC 在 mac_to_port 表中的話，就直接告訴 Switch 送到 out_port
        # 否則就請 Switch 用 Flooding 送出去
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        # 把剛剛的 out_port 作成這次封包的處理動作
        actions = [parser.OFPActionOutput(out_port)]

        # 如果沒有讓 switch flooding，表示目的端 mac 有學習過
        # 因此使用 add_flow 讓 Switch 新增 FlowEntry 學習此筆規則

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath,0, 1, match,0, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port)
        # 把要 Switch 執行的動作包裝成 Packet_out，並讓 Switch 執行動作
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=match, actions=actions, data=data)
        datapath.send_msg(out) #將封包傳送回ovs
