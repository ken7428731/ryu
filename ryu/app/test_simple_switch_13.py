# -*- coding: utf-8 -*-
#參考 https://gist.github.com/aweimeow/d3662485aa224d298e671853aadb2d0f 的基本教學

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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp

from scada_log.write_log_txt import write_log
from scada_log.epoch_to_datetime import epoch_to_datetime
from ryu.lib.packet import modbus_tcp

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.modbus_tcp_information=[]
        self.write_log_object=write_log()
        self.write_log_object.delete_old_log_file()
        self.datetime_object=epoch_to_datetime()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) #程式開始執行時，會先到這裡針對OvS設定相關的資訊
    # set_ev_cls(ev_cls, dispatchers=None): 事件接收
    # set_ev_cls 為 是一個用於將方法註冊成 Ryu 事件處理器的一個修飾器，被修飾的 方法將會成為一個事件處理器。
    # dispatchers 為 該事件處理器將會在哪些談判階段（negotiation phases） 去接收此一類型的事件。
    def switch_features_handler(self, ev):# 一開始 Switch 連上 Controller 時的初始設定 Function
        datapath = ev.msg.datapath # 接收 OpenFlow 交換器實例
        ofproto = datapath.ofproto # OpenFlow 交換器使用的 OpenFlow 協定版本
        parser = datapath.ofproto_parser # 處理 OpenFlow 協定的 parser(解析)

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
        self.add_flow(datapath, 0, match, actions)
    #---------新增flow到ovs上----------
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # 取得與 Switch 使用的 IF 版本 對應的 OF 協定及 parser
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Instructions 是定義當封包滿足 match 時，所要執行的動作
        # 因此把 action 以 OFPInstructionActions 包裝起來
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
             # FlowMod Function 可以讓我們對 Switch 寫入由我們所定義的 Flow Entry
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    # 處理ovs傳送過來的封包
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        # self.write_log_object.write_log_txt_2("ev.msg="+str(msg))
        print("-----------------------")
        self.packet_timestamp=getattr(ev, 'timestamp', None) #取得 ev 裡面的 timestamp 。getattr 『取得』class 內定義變數的值
        self.packet_datetime=self.datetime_object.get_datetime(self.packet_timestamp)
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        print('in_port='+str(in_port))

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        if self.pkt.get_protocols(ipv4.ipv4):
            self.ipv4=self.pkt.get_protocols(ipv4.ipv4)[0]
            self.ipv4_src = self.ipv4.src
            self.ipv4_dst = self.ipv4.dst
            self.ipv4_protocol=self.ipv4.proto
            self.ipv4_services=self.ipv4.tos
        if self.pkt.get_protocols(tcp.tcp):
            self.tcp=self.pkt.get_protocols(tcp.tcp)[0]
            self.tcp_src_port=self.tcp.src_port
            self.tcp_dst_port=self.tcp.dst_port
            self.tcp_seq_number=self.tcp.seq
            self.tcp_ack=self.tcp.ack
            self.tcp_flags=self.tcp.bits
        #----- 顯示ipv4與tcp的內容
        if self.pkt.get_protocols(ipv4.ipv4):
            print("ipv4_src="+str(self.ipv4_src))
            print("ipv4_dst="+str(self.ipv4_dst))
        if self.pkt.get_protocols(tcp.tcp):
            print("tcp="+str(self.tcp))
            print("tcp_seq_number="+str(self.tcp_seq_number))

        #---------將資料寫到log檔----------------
        if self.pkt.get_protocols(tcp.tcp):
            self.write_log_object.write_log_txt("-----------------")
            self.write_log_object.write_log_txt("ev="+str(ev))
            self.write_log_object.write_log_txt("ev.msg="+str(ev.msg))
            self.write_log_object.write_log_txt("packet_timestamp="+str(self.packet_timestamp))
            self.write_log_object.write_log_txt("packet_datetime="+str(self.packet_datetime))
            self.write_log_object.write_log_txt("ev.msg.data="+str(self.data))
            self.write_log_object.write_log_txt("datapath="+str(self.datapath))
            self.write_log_object.write_log_txt("parser="+str(self.parser))
            self.write_log_object.write_log_txt("in_port="+str(self.in_port))
            self.write_log_object.write_log_txt("pkt="+str(self.pkt))
            # self.write_log_object.write_log_txt("pkt_len="+str(self.pkt.__len__()))
            self.write_log_object.write_log_txt("eth="+str(self.eth))
            self.write_log_object.write_log_txt("dst="+str(self.dst))
            self.write_log_object.write_log_txt("src="+str(self.src))
            # if self.pkt.get_protocols(ipv4.ipv4):
            self.write_log_object.write_log_txt("ipv4="+str(self.ipv4))
            self.write_log_object.write_log_txt("ipv4.src="+str(self.ipv4_src))
            self.write_log_object.write_log_txt("ipv4.dst="+str(self.ipv4_dst))
            # if self.pkt.get_protocols(tcp.tcp):
            self.write_log_object.write_log_txt("tcp="+str(self.tcp))
            self.write_log_object.write_log_txt("tcp_src_port="+str(self.tcp_src_port))
            self.write_log_object.write_log_txt("tcp_dst_port="+str(self.tcp_dst_port))
            self.write_log_object.write_log_txt("tcp_seq_number="+str(self.tcp_seq_number))
        
        #----------------- 儲存 TCP連線狀態時間------------------------------------------------------#
            if self.tcp_dst_port==502 and self.tcp.has_flags(tcp.TCP_SYN): #modbus_tcp 建立連線
                self.temp_date_list={}
                self.temp_date_list['ipv4_src']=self.ipv4_src
                self.temp_date_list['ipv4_dst']=self.ipv4_dst
                self.temp_date_list['src_port']=self.tcp_src_port
                self.temp_date_list['dst_port']=self.tcp_dst_port
                self.temp_date_list['tcp_connection_time']=[]
                self.temp_tcp_connection_time={}
                self.temp_tcp_connection_time_array=[]
                if len(self.modbus_tcp_information)>0:
                    for i in range(len(self.modbus_tcp_information)):
                        if self.modbus_tcp_information[i]['ipv4_src']==self.ipv4_src and self.modbus_tcp_information[i]['ipv4_dst']==self.ipv4_dst and len(self.modbus_tcp_information[i]['tcp_connection_time'])>0:
                            self.temp_tcp_connection_time={}
                            self.temp_tcp_connection_time_array=[]
                            self.temp_tcp_connection_time['tcp_syn_time']=self.packet_timestamp
                            self.temp_tcp_connection_time_array.append(self.temp_tcp_connection_time)
                            self.modbus_tcp_information[i]['tcp_connection_time'].append(self.temp_tcp_connection_time_array)
                        else:
                            self.temp_tcp_connection_time['tcp_syn_time']=self.packet_timestamp
                            self.temp_tcp_connection_time_array.append(self.temp_tcp_connection_time)
                            self.temp_date_list['tcp_connection_time'].append(self.temp_tcp_connection_time_array)
                            self.modbus_tcp_information.append(self.temp_date_list)
                else:
                    self.temp_tcp_connection_time['tcp_syn_time']=self.packet_timestamp
                    self.temp_tcp_connection_time_array.append(self.temp_tcp_connection_time)
                    self.temp_date_list['tcp_connection_time'].append(self.temp_tcp_connection_time_array)
                    self.modbus_tcp_information.append(self.temp_date_list)
                print('packet_is:SYN')
                self.write_log_object.write_log_txt('packet_is:SYN')
                print('self.modbus_tcp_information='+str(self.modbus_tcp_information))
                self.write_log_object.write_log_txt('self.modbus_tcp_information='+str(self.modbus_tcp_information))
            # self.tcp.
            if self.tcp_src_port==502  and self.tcp.has_flags(tcp.TCP_FIN,tcp.TCP_ACK): #modbus_tcp 斷線
                if len(self.modbus_tcp_information)>0:
                    for i in range(len(self.modbus_tcp_information)):
                        if self.modbus_tcp_information[i]['ipv4_src']==self.ipv4_dst and self.modbus_tcp_information[i]['ipv4_dst']==self.ipv4_src and len(self.modbus_tcp_information[i]['tcp_connection_time'])>0:
                            for j in range(len(self.modbus_tcp_information[i]['tcp_connection_time'])):
                                if len(self.modbus_tcp_information[i]['tcp_connection_time'][j][0])<2:
                                    self.modbus_tcp_information[i]['tcp_connection_time'][j][0]['tcp_fin_time']=self.packet_timestamp #放入結束時間
                                    #計算 duration_time
                                    self.modbus_tcp_information[i]['tcp_connection_time'][j][0]['duration_time']=self.modbus_tcp_information[i]['tcp_connection_time'][j][0]['tcp_fin_time']-self.modbus_tcp_information[i]['tcp_connection_time'][j][0]['tcp_syn_time']
                print('packet_is:FIN')
                self.write_log_object.write_log_txt('packet_is:FIN')
                print('self.modbus_tcp_information='+str(self.modbus_tcp_information))
                self.write_log_object.write_log_txt('self.modbus_tcp_information='+str(self.modbus_tcp_information))

            #------------------------------------解析Modbus TCP(應用層)的部分 ------------------------------------#
            if self.pkt.__len__()==4 and (self.tcp_src_port==502 or self.tcp_dst_port==502):
                self.write_log_object.write_log_txt("---------modbus tcp-------------")
                #錄製modbus tcp 的封包
                self.packet_save_object.write_packet_timestamp_to_txt(self.packet_timestamp)
                self.packet_save_object.write_packet_to_txt(self.pkt)
                
                print("__iter__="+str(self.pkt.__iter__()))
                print("__len__="+str(self.pkt.__len__()))
                print("__getitem__="+str(self.pkt.__getitem__(3)))
                self.write_log_object.write_log_txt("__iter__="+str(self.pkt.__iter__()))
                self.write_log_object.write_log_txt("__len__="+str(self.pkt.__len__()))
                self.write_log_object.write_log_txt("__getitem__="+str(self.pkt.__getitem__(3)))
                
                mb=modbus_tcp.modbus_tcp()
                mb.get_modbus_tcp(self.tcp_src_port,self.tcp_dst_port,self.pkt.__getitem__(3))
                self.write_log_object.write_log_txt("****************")
                self.write_log_object.write_log_txt("mb.t_id="+str(mb.t_id))
                self.write_log_object.write_log_txt("mb.p_id="+str(mb.p_id))
                self.write_log_object.write_log_txt("mb.modbus_len="+str(mb.modbus_len))
                self.write_log_object.write_log_txt("mb.u_id="+str(mb.u_id))
                if self.tcp_dst_port==502: #request 
                    print("*****request >>>> *****")
                    print("mb.fun_code="+str(mb.fun_code))
                    self.write_log_object.write_log_txt("*****request >>>> *****")
                    self.write_log_object.write_log_txt("mb.fun_code="+str(mb.fun_code))
                    if mb.fun_code==5:
                        print("mb.reference_number="+str(mb.reference_number))
                        print("mb.modbus_5_data="+str(mb.modbus_5_data))
                        self.write_log_object.write_log_txt("mb.reference_number="+str(mb.reference_number))
                        self.write_log_object.write_log_txt("mb.modbus_5_data="+str(mb.modbus_5_data))
                    else:
                        print("mb.reference_number="+str(mb.reference_number))
                        print("mb.Bit_Count="+str(mb.Bit_Count))
                        print("mb.data_lenth="+str(mb.data_lenth))
                        self.write_log_object.write_log_txt("mb.reference_number="+str(mb.reference_number))
                        self.write_log_object.write_log_txt("mb.Bit_Count="+str(mb.Bit_Count))                    
                        self.write_log_object.write_log_txt("mb.data_lenth="+str(mb.data_lenth))
                elif self.tcp_src_port==502: # response
                    print("*****response <<<<< *****")
                    print("mb.fun_code="+str(mb.fun_code))
                    self.write_log_object.write_log_txt("*****response <<<<< *****")
                    self.write_log_object.write_log_txt("mb.fun_code="+str(mb.fun_code))
                    if mb.fun_code==5:
                        print("mb.reference_number="+str(mb.reference_number))
                        print("mb.modbus_5_data="+str(mb.modbus_5_data))
                        self.write_log_object.write_log_txt("mb.reference_number="+str(mb.reference_number))
                        self.write_log_object.write_log_txt("mb.modbus_5_data="+str(mb.modbus_5_data))
                    else:
                        print("mb.byte_count="+str(mb.byte_count))
                        print("mb.modbus_data="+str(mb.modbus_data))
                        self.write_log_object.write_log_txt("mb.byte_count="+str(mb.byte_count))
                        self.write_log_object.write_log_txt("mb.modbus_data="+str(mb.modbus_data))

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
