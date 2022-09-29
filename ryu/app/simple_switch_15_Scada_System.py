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
#[1] https://stackoverflow.com/questions/49971882/delete-flows-matching-specific-cookie-openflow-1-3-5-spec-support-by-openvswit
# https://gist.github.com/aweimeow/d3662485aa224d298e671853aadb2d0f 的基本教學


from typing import Counter
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
from scada_log.epoch_to_datetime import epoch_to_datetime
import threading
from ryu.lib.packet import modbus_tcp
from ryu.lib import hub
import copy

RULE_0_TABLE=0
RULE_1_TABLE=1
RULE_2_TABLE=2
RULE_3_TABLE=3
RULE_4_TABLE=4
RULE_5_TABLE=5
RULE_6_TABLE=6
SCADA_Information_List=[]
temp_SCADA_Information_List=[]

Modbus_Tcp_Packet_In_Information_Table=[] #rule 1
Modbus_Tcp_Syn_Information_Table=[] #rule 2
Modbus_Tcp_Connection_Information_Table=[] #rule 3

Device_IP_List=[]

Factory_Block_Table=[]

rule_table_2_set_list=[]
rule_2_full_state=0
rule_3_set_state_list=[]
modbus_tcp_function_list=[] #rule 4 #判斷封包的功能是否一樣
modbus_tcp_function_data_list=[] #rule 5 #判斷封包的值是否超過範圍
flow_entry_list=[]
temp_flow_entry_list=[]
flow_entry_list_json=[]

first_switch_features=[]



class SimpleSwitch15(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_5.OFP_VERSION]
    

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch15, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.ip_to_port = {}

        self.write_log_object=write_log()
        self.write_log_object.delete_old_log_file()

        
        self.datetime_object=epoch_to_datetime()

        self.load_Device_Information_thread=hub.spawn(self.Load_SCADA_Information) #建立執行續(讀取設定檔)
        self.load_Device_Information_thread_2=hub.spawn(self.Set_Device_Information_List) #建立執行續(類似白名單感覺)

    def Load_SCADA_Information(self): #讀取Device_Information.json資訊
        global SCADA_Information_List
        global temp_SCADA_Information_List
        global rule_3_set_state_list
        temp_list=[]
        self.Load_SCADA_Information_Object=Load_Data()
        while True:
            temp=self.Load_SCADA_Information_Object.Load_Information()
            for i in range(len(temp['PLC_Device'])):
                for j in range(len(temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'])):
                    self.tempp={}
                    if temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['model']=='Coil':
                        self.tempp['model']=1
                        self.tempp['Start']=temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['Start']
                        self.tempp['Range']=temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['End']-temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['Start']
                        if self.tempp['Range']>0:
                            self.tempp['Range']=self.tempp['Range']-1
                    elif temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['model']=='M':
                        self.tempp['model']=1
                        self.tempp['Start']=temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['Start']
                        self.tempp['Range']=temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['End']-temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['Start']
                        if self.tempp['Range']>0:
                            self.tempp['Range']=self.tempp['Range']+1
                    elif temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['model']=='X_Input':
                        self.tempp['model']=2
                        self.tempp['Start']=temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['Start']
                        self.tempp['Range']=temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['End']-temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['Start']
                        if self.tempp['Range']>0:
                            self.tempp['Range']=self.tempp['Range']+1
                    elif temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['model']=='D':
                        self.tempp['model']=3
                        self.tempp['Start']=temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['Start']
                        self.tempp['Range']=temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['End']-temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]['Start']
                        if self.tempp['Range']>0:
                            self.tempp['Range']=self.tempp['Range']+1
                    temp['PLC_Device'][i]['PLC_Device_GPIO_Open_State'][j]=self.tempp
            SCADA_Information_List=temp
            self.write_log_object.write_log_txt('Load_SCADA_Information_before='+str(temp))
            if len(temp_SCADA_Information_List)>0:
                if temp_SCADA_Information_List!=SCADA_Information_List:
                    self.Set_Device_Information_List()
                    if len(SCADA_Information_List['HMI_Device_IP'])>len(temp_SCADA_Information_List['HMI_Device_IP']):
                        self.ttemp={}
                        self.ttemp['HMI_Device_IP']=[]
                        for i in range(len(SCADA_Information_List['HMI_Device_IP'])):
                            a=[temp for temp in temp_SCADA_Information_List['HMI_Device_IP'] if temp==SCADA_Information_List['HMI_Device_IP'][i]] 
                            if len(a)<=0:
                                self.ttemp['HMI_Device_IP'].append(SCADA_Information_List['HMI_Device_IP'][i])
                                self.add_Factory_Block_Table(SCADA_Information_List['HMI_Device_IP'][i])
                        temp_list.append(self.ttemp)
                    elif len(SCADA_Information_List['HMI_Device_IP'])==len(temp_SCADA_Information_List['HMI_Device_IP']):
                        self.ttemp={}
                        self.ttemp['HMI_Device_IP']=[]
                        for i in range(len(SCADA_Information_List['HMI_Device_IP'])):
                            a=[temp for temp in temp_SCADA_Information_List['HMI_Device_IP'] if temp==SCADA_Information_List['HMI_Device_IP'][i]] 
                            if len(a)<=0:
                                self.ttemp['HMI_Device_IP'].append(SCADA_Information_List['HMI_Device_IP'][i])
                                self.Set_change_Device_Information(temp_SCADA_Information_List['HMI_Device_IP'][i],SCADA_Information_List['HMI_Device_IP'][i])
                        temp_list.append(self.ttemp)
                    elif len(SCADA_Information_List['HMI_Device_IP'])<len(temp_SCADA_Information_List):
                        self.ttemp={}
                        self.ttemp['HMI_Device_IP']=[]
                        for i in range(len(temp_SCADA_Information_List['HMI_Device_IP'])):
                            a=[temp for temp in SCADA_Information_List['HMI_Device_IP'] if temp==temp_SCADA_Information_List['HMI_Device_IP'][i]] 
                            if len(a)<=0:
                                self.ttemp['HMI_Device_IP'].append(temp_SCADA_Information_List['HMI_Device_IP'][i])
                                self.del_Factory_Block_Table(temp_SCADA_Information_List['HMI_Device_IP'][i])
                                # self.write_log_object.write_log_txt('HMI Delete='+str(temp_SCADA_Information_List['HMI_Device_IP'][i]))
                        temp_list.append(self.ttemp)
                    if len(SCADA_Information_List['PLC_Device'])>len(temp_SCADA_Information_List['PLC_Device']):
                        self.ttemp={}
                        self.ttemp['PLC_Device']=[]
                        for i in range(len(SCADA_Information_List['PLC_Device'])):
                            a=[temp for temp in temp_SCADA_Information_List['PLC_Device'] if temp['IP']==SCADA_Information_List['PLC_Device'][i]['IP']] 
                            if len(a)<=0:
                                self.tttemp={}
                                self.tttemp['IP']=SCADA_Information_List['PLC_Device'][i]['IP']
                                self.ttemp['PLC_Device'].append(self.tttemp)
                                # self.write_log_object.write_log_txt('add self.ttemp='+str(self.ttemp))
                                self.add_prottect_Device(SCADA_Information_List['PLC_Device'][i]['IP'])
                        temp_list.append(self.ttemp)

                    elif len(SCADA_Information_List['PLC_Device'])==len(temp_SCADA_Information_List['PLC_Device']):
                        self.ttemp={}
                        self.ttemp['PLC_Device']=[]
                        for i in range(len(SCADA_Information_List['PLC_Device'])):
                            a=[temp for temp in temp_SCADA_Information_List['PLC_Device'] if temp['IP']==SCADA_Information_List['PLC_Device'][i]['IP']] 
                            if len(a)<=0:
                                self.tttemp={}
                                self.tttemp['IP']=SCADA_Information_List['PLC_Device'][i]['IP']
                                self.ttemp['PLC_Device'].append(self.tttemp)
                                self.Set_change_Device_Information(temp_SCADA_Information_List['PLC_Device'][i]['IP'],SCADA_Information_List['PLC_Device'][i]['IP'])
                        temp_list.append(self.ttemp)
                    elif len(SCADA_Information_List['PLC_Device'])<len(temp_SCADA_Information_List['PLC_Device']):
                        self.ttemp={}
                        self.ttemp['PLC_Device']=[]
                        for i in range(len(temp_SCADA_Information_List['PLC_Device'])):
                            a=[temp for temp in SCADA_Information_List['PLC_Device'] if temp['IP']==temp_SCADA_Information_List['PLC_Device'][i]['IP']] 
                            if len(a)<=0:
                                self.tttemp={}
                                self.tttemp['IP']=temp_SCADA_Information_List['PLC_Device'][i]['IP']
                                self.ttemp['PLC_Device'].append(self.tttemp)
                                # self.write_log_object.write_log_txt('del self.ttemp='+str(self.ttemp))
                                self.del_prottect_Device(temp_SCADA_Information_List['PLC_Device'][i]['IP'])
                        temp_list.append(self.ttemp)

                    if len(SCADA_Information_List['Facyory_Device_IP'])>len(temp_SCADA_Information_List['Facyory_Device_IP']):
                        self.ttemp={}
                        self.ttemp['Facyory_Device_IP']=[]
                        for i in range(len(SCADA_Information_List['Facyory_Device_IP'])):
                            a=[temp for temp in temp_SCADA_Information_List['Facyory_Device_IP'] if temp==SCADA_Information_List['Facyory_Device_IP'][i]] 
                            if len(a)<=0:
                                self.ttemp['Facyory_Device_IP'].append(SCADA_Information_List['Facyory_Device_IP'][i])
                                self.add_Factory_Block_Table(SCADA_Information_List['Facyory_Device_IP'][i])
                                self.write_log_object.write_log_txt('add_self.ttemp='+str(self.ttemp))
                        temp_list.append(self.ttemp)
                    elif len(SCADA_Information_List['Facyory_Device_IP'])==len(temp_SCADA_Information_List['Facyory_Device_IP']):
                        self.ttemp={}
                        self.ttemp['Facyory_Device_IP']=[]
                        for i in range(len(SCADA_Information_List['Facyory_Device_IP'])):
                            a=[temp for temp in temp_SCADA_Information_List['Facyory_Device_IP'] if temp==SCADA_Information_List['Facyory_Device_IP'][i]] 
                            if len(a)<=0:
                                self.ttemp['Facyory_Device_IP'].append(SCADA_Information_List['Facyory_Device_IP'][i])
                                self.Set_change_Device_Information(temp_SCADA_Information_List['Facyory_Device_IP'][i],SCADA_Information_List['Facyory_Device_IP'][i])
                        temp_list.append(self.ttemp)
                    elif len(SCADA_Information_List['Facyory_Device_IP'])<len(temp_SCADA_Information_List):
                        self.ttemp={}
                        self.ttemp['Facyory_Device_IP']=[]
                        for i in range(len(temp_SCADA_Information_List['Facyory_Device_IP'])):
                            a=[temp for temp in SCADA_Information_List['Facyory_Device_IP'] if temp==temp_SCADA_Information_List['Facyory_Device_IP'][i]] 
                            if len(a)<=0:
                                self.ttemp['Facyory_Device_IP'].append(temp_SCADA_Information_List['Facyory_Device_IP'][i])
                                self.del_Factory_Block_Table(temp_SCADA_Information_List['Facyory_Device_IP'][i])
                                self.write_log_object.write_log_txt('del_self.ttemp='+str(self.ttemp))
                        temp_list.append(self.ttemp)

                    if len(SCADA_Information_List['Allow_Service_IP'])>len(temp_SCADA_Information_List['Allow_Service_IP']):
                        self.ttemp={}
                        self.ttemp['Allow_Service_IP']=[]
                        for i in range(len(SCADA_Information_List['Allow_Service_IP'])):
                            a=[temp for temp in temp_SCADA_Information_List['Allow_Service_IP'] if temp==SCADA_Information_List['Allow_Service_IP'][i]] 
                            if len(a)<=0:
                                self.ttemp['Allow_Service_IP'].append(SCADA_Information_List['Allow_Service_IP'][i])
                                self.add_Factory_Block_Table(SCADA_Information_List['Allow_Service_IP'][i])
                                self.write_log_object.write_log_txt('add_self.ttemp='+str(self.ttemp))
                        temp_list.append(self.ttemp)
                    elif len(SCADA_Information_List['Allow_Service_IP'])==len(temp_SCADA_Information_List['Allow_Service_IP']):
                        self.ttemp={}
                        self.ttemp['Allow_Service_IP']=[]
                        for i in range(len(SCADA_Information_List['Allow_Service_IP'])):
                            a=[temp for temp in temp_SCADA_Information_List['Allow_Service_IP'] if temp==SCADA_Information_List['Allow_Service_IP'][i]] 
                            if len(a)<=0:
                                self.ttemp['Allow_Service_IP'].append(SCADA_Information_List['Allow_Service_IP'][i])
                                self.Set_change_Device_Information(temp_SCADA_Information_List['Allow_Service_IP'][i],SCADA_Information_List['Allow_Service_IP'][i])
                        temp_list.append(self.ttemp)
                    elif len(SCADA_Information_List['Allow_Service_IP'])<len(temp_SCADA_Information_List):
                        self.ttemp={}
                        self.ttemp['Allow_Service_IP']=[]
                        for i in range(len(temp_SCADA_Information_List['Allow_Service_IP'])):
                            a=[temp for temp in SCADA_Information_List['Allow_Service_IP'] if temp==temp_SCADA_Information_List['Allow_Service_IP'][i]] 
                            if len(a)<=0:
                                self.ttemp['Allow_Service_IP'].append(temp_SCADA_Information_List['Allow_Service_IP'][i])
                                self.del_Factory_Block_Table(temp_SCADA_Information_List['Allow_Service_IP'][i])
                                self.write_log_object.write_log_txt('del_self.ttemp='+str(self.ttemp))
                        temp_list.append(self.ttemp)
                    if SCADA_Information_List['PLC_Allow_Connect_number']>temp_SCADA_Information_List['PLC_Allow_Connect_number']:
                        self.del_policy_3_all_block_flow()
                    # elif SCADA_Information_List['PLC_Allow_Connect_number']<temp_SCADA_Information_List['PLC_Allow_Connect_number']:
                    #     self.del_policy_3_all_block_flow()


                    self.write_log_object.write_log_txt('Device_information_is_change_after='+str(temp_list))
                    temp_SCADA_Information_List=copy.deepcopy(SCADA_Information_List)
                    
            else:
                temp_SCADA_Information_List=copy.deepcopy(SCADA_Information_List)
            
            self.write_log_object.write_log_txt('Load_SCADA_Information='+str(SCADA_Information_List))
            temp_list=[]
            hub.sleep(1)
    def add_prottect_Device(self,prottect_ip=None):
        global first_switch_features
        if len(first_switch_features)>0:
            for i in range(len(first_switch_features)):
                self.priority=10
                self.datapath=first_switch_features[i]['datapath']
                self.parser=self.datapath.ofproto_parser
                self.table_id=0
                self.match_1=self.parser.OFPMatch(eth_type=0x0800,ipv4_dst=prottect_ip)
                self.inst= [self.parser.OFPInstructionGotoTable(RULE_1_TABLE)] #Go to The Table 1
                self.add_flow(self.datapath,self.table_id, self.priority, self.match_1, self.inst,state='rule') #在table 0比對到 往table 1送      
                self.Record_set_flow_entry(self.datapath,self.table_id,self.priority,0,prottect_ip,inst=self.inst) #rule 0
                self.match_2=self.parser.OFPMatch(eth_type=0x0800,ipv4_src=prottect_ip)
                self.add_flow(self.datapath,self.table_id, self.priority, self.match_2, self.inst,state='rule') #在table 0比對到 往table 1送      

    def del_prottect_Device(self,prottect_ip=None):
        global first_switch_features
        if len(first_switch_features)>0:
            for i in range(len(first_switch_features)):
                self.priority=10
                self.datapath=first_switch_features[i]['datapath']
                self.parser=self.datapath.ofproto_parser
                self.table_id=0
                self.match_1=self.parser.OFPMatch(eth_type=0x0800,ipv4_dst=prottect_ip)
                self.delete_flow(self.datapath,self.table_id,self.priority,self.match_1)
                self.match_2=self.parser.OFPMatch(eth_type=0x0800,ipv4_src=prottect_ip)
                self.delete_flow(self.datapath,self.table_id,self.priority,self.match_2)
    def del_policy_3_all_block_flow(self):
        global rule_3_set_state_list
        for i in range(len(rule_3_set_state_list)):
            self.priority=5
            self.datapath=rule_3_set_state_list[i]['datapath']
            self.table_2_match= self.datapath.ofproto_parser.OFPMatch()
            self.delete_flow(self.datapath,RULE_2_TABLE,self.priority,self.table_2_match)
            rule_3_set_state_list[i]['rule_3_set_all_packet_block']='False'
        self.write_log_object.write_log_txt('del_policy_3_all_block_flow is on')
        
    def Set_Device_Information_List(self):
        global Device_IP_List
        if len(SCADA_Information_List)>0:
            if len(SCADA_Information_List['HMI_Device_IP'])>0:
                for i in range(len(SCADA_Information_List['HMI_Device_IP'])):
                    Device_IP_List.append(SCADA_Information_List['HMI_Device_IP'][i])
            if len(SCADA_Information_List['PLC_Device'])>0:
                for i in range(len(SCADA_Information_List['PLC_Device'])):
                    Device_IP_List.append(SCADA_Information_List['PLC_Device'][i]['IP'])
            if len(SCADA_Information_List['Facyory_Device_IP'])>0:
                for i in range(len(SCADA_Information_List['Facyory_Device_IP'])):
                    Device_IP_List.append(SCADA_Information_List['Facyory_Device_IP'][i])
            if len(SCADA_Information_List['Allow_Service_IP'])>0:
                for i in range(len(SCADA_Information_List['Allow_Service_IP'])):
                    Device_IP_List.append(SCADA_Information_List['Allow_Service_IP'][i])
            self.write_log_object.write_log_txt('Device_IP_List= '+str(Device_IP_List))
        hub.sleep(1)
    def Record_set_flow_entry(self,datapath,table_id,priority,rule,one_ip,two_ip=None,inst=0,actions=None):
        global flow_entry_list_json
        self.temp_json={}
        self.temp_json['datapath']=datapath
        self.temp_json['priority']=priority
        self.temp_json['rule']=rule
        self.temp_json['table_id']=table_id
        if rule==0:
            self.temp_json['rule']=rule
            self.temp_json['one_ip']=one_ip
            self.temp_json['inst']=inst
            flow_entry_list_json.append(self.temp_json)
            
        if rule==1:
            self.temp_json['rule']=rule
            self.temp_json['one_ip']=one_ip
            self.temp_json['actions']=actions
            flow_entry_list_json.append(self.temp_json)
        if rule==2:
            self.temp_json['rule']=rule
            self.temp_json['one_ip']=one_ip
            self.temp_json['actions']=actions
            flow_entry_list_json.append(self.temp_json)
        if rule==3:
            self.temp_json['rule']=rule
            self.temp_json['one_ip']=one_ip
            self.temp_json['two_ip']=two_ip
            self.temp_json['inst']=inst
            flow_entry_list_json.append(self.temp_json)
        if rule==4:
            self.temp_json['rule']=rule
            self.temp_json['one_ip']=one_ip
            self.temp_json['actions']=actions
            flow_entry_list_json.append(self.temp_json)
        if rule==5:
            self.temp_json['rule']=rule
            self.temp_json['one_ip']=one_ip
            self.temp_json['actions']=actions
            flow_entry_list_json.append(self.temp_json)
        self.write_log_object.write_log_txt('Record_set_flow_entry='+str(flow_entry_list_json))
    def Set_change_Device_Information(self,before_ip,after_ip):
        global SCADA_Information_List
        global flow_entry_list_json
        global Modbus_Tcp_Packet_In_Information_Table #rule 1
        global Modbus_Tcp_Syn_Information_Table #rule 2
        global Modbus_Tcp_Connection_Information_Table #rule 3
        global modbus_tcp_function_list #rule 4 #判斷封包的功能是否一樣
        global modbus_tcp_function_data_list #rule 5 #判斷封包的值是否超過範圍
        global Factory_Block_Table #是否允許將ip阻擋
        for i in range(len(flow_entry_list_json)):
            if (flow_entry_list_json[i]['rule']==0) and (flow_entry_list_json[i]['one_ip']==before_ip):
                self.datapath=flow_entry_list_json[i]['datapath']
                self.parser=self.datapath.ofproto_parser
                self.table_id=flow_entry_list_json[i]['table_id']
                self.priority=flow_entry_list_json[i]['priority']
                self.temp_before_match_1=self.parser.OFPMatch(eth_type=0x0800,ipv4_dst=before_ip)
                self.temp_before_match_2=self.parser.OFPMatch(eth_type=0x0800,ipv4_src=before_ip)
                self.delete_flow(self.datapath,self.table_id,self.priority,self.temp_before_match_1)
                self.delete_flow(self.datapath,self.table_id,self.priority,self.temp_before_match_2)
                self.temp_after_match_1=self.parser.OFPMatch(eth_type=0x0800,ipv4_dst=after_ip)
                self.temp_after_match_2=self.parser.OFPMatch(eth_type=0x0800,ipv4_src=after_ip)
                self.inst=flow_entry_list_json[i]['inst']
                del flow_entry_list_json[i]
                self.Set_Change_global_list(before_ip,after_ip)
                self.add_flow(self.datapath,self.table_id,self.priority,self.temp_after_match_1,inst=self.inst)
                self.add_flow(self.datapath,self.table_id,self.priority,self.temp_after_match_2,inst=self.inst)
                self.Record_set_flow_entry(self.datapath,self.table_id,self.priority,0,after_ip,inst=self.inst)      
            elif (flow_entry_list_json[i]['rule']==3) and (flow_entry_list_json[i]['two_ip']==before_ip):
                self.datapath=flow_entry_list_json[i]['datapath']
                self.parser=self.datapath.ofproto_parser
                self.table_id=flow_entry_list_json[i]['table_id']
                self.priority=flow_entry_list_json[i]['priority']
                self.before_one_ip=flow_entry_list_json[i]['one_ip']
                self.before_two_ip=flow_entry_list_json[i]['two_ip']
                self.temp_before_match_1= self.parser.OFPMatch(eth_type=0x0800,ip_proto=0x6,ipv4_src=self.before_one_ip,ipv4_dst=self.before_two_ip)
                self.temp_before_match_2= self.parser.OFPMatch(eth_type=0x0800,ip_proto=0x6,ipv4_src=self.before_two_ip,ipv4_dst=self.before_one_ip)
                self.delete_flow(self.datapath,self.table_id,self.priority,self.temp_before_match_1)
                self.delete_flow(self.datapath,self.table_id,self.priority,self.temp_before_match_2)
                self.after_one_ip=flow_entry_list_json[i]['one_ip']
                self.after_two_ip=after_ip
                self.temp_after_match_1= self.parser.OFPMatch(eth_type=0x0800,ip_proto=0x6,ipv4_src=self.after_one_ip,ipv4_dst=self.after_two_ip)
                self.temp_after_match_2= self.parser.OFPMatch(eth_type=0x0800,ip_proto=0x6,ipv4_src=self.after_two_ip,ipv4_dst=self.after_one_ip)
                self.inst=flow_entry_list_json[i]['inst']
                del flow_entry_list_json[i]
                self.Set_Change_global_list(before_ip,after_ip)
                self.add_flow(self.datapath,self.table_id,self.priority,self.temp_after_match_1,inst=self.inst)
                self.add_flow(self.datapath,self.table_id,self.priority,self.temp_after_match_2,inst=self.inst)
                self.Record_set_flow_entry(self.datapath,self.table_id,self.priority,3,self.after_one_ip,self.after_two_ip,inst=self.inst)
            elif ((flow_entry_list_json[i]['rule']==1) or (flow_entry_list_json[i]['rule']==2) or (flow_entry_list_json[i]['rule']==4) or (flow_entry_list_json[i]['rule']==5)) and (flow_entry_list_json[i]['one_ip']==before_ip):
                self.write_log_object.write_log_txt('change_before')
                self.datapath=flow_entry_list_json[i]['datapath']
                self.parser=self.datapath.ofproto_parser
                self.table_id=flow_entry_list_json[i]['table_id']
                self.priority=flow_entry_list_json[i]['priority']
                self.actions=flow_entry_list_json[i]['actions']
                self.rule_id=flow_entry_list_json[i]['rule']
                # self.write_log_object.write_log_txt('change_before_'+str(flow_entry_list_json[i]['rule'])+',datapath='+str(self.datapath))
                # self.write_log_object.write_log_txt('change_before_'+str(flow_entry_list_json[i]['rule'])+',table_id='+str(self.table_id))
                # self.write_log_object.write_log_txt('change_before_'+str(flow_entry_list_json[i]['rule'])+',priority='+str(self.priority))
                self.temp_before_match_1= self.parser.OFPMatch(eth_type=0x0800,ipv4_src=before_ip)
                self.delete_flow(self.datapath,self.table_id,self.priority,self.temp_before_match_1)
                # self.write_log_object.write_log_txt('delete is ok')
                # self.write_log_object.write_log_txt('flow_entry_list_json_before='+str(flow_entry_list_json))
                # self.write_log_object.write_log_txt('flow_entry_list_json_after='+str(flow_entry_list_json))
                # self.write_log_object.write_log_txt('change_policy_'+str(flow_entry_list_json[i]['rule'])+',datapath='+str(self.datapath))
                # self.write_log_object.write_log_txt('change_policy_'+str(flow_entry_list_json[i]['rule'])+',table_id='+str(self.table_id))
                # self.write_log_object.write_log_txt('change_policy_'+str(flow_entry_list_json[i]['rule'])+',priority='+str(self.priority))
                self.temp_after_match_1= self.parser.OFPMatch(eth_type=0x0800,ipv4_src=after_ip)
                self.Set_Change_global_list(before_ip,after_ip)
                # self.write_log_object.write_log_txt('change_policy_'+str(self.rule_id)+',temp_after_match_1='+str(self.temp_after_match_1))
                # self.write_log_object.write_log_txt('change_policy_'+str(self.rule_id)+',actions='+str(self.actions))
                self.add_flow(self.datapath,self.table_id, self.priority, self.temp_after_match_1,actions=self.actions)
                # self.write_log_object.write_log_txt('change_after')
                del flow_entry_list_json[i]
                self.Record_set_flow_entry(self.datapath,self.table_id,self.priority,self.rule_id,after_ip,actions=self.actions)
    
    def Set_Change_global_list(self,before_ip,after_ip):
        global Modbus_Tcp_Packet_In_Information_Table #rule 1
        global Modbus_Tcp_Syn_Information_Table #rule 2
        global Modbus_Tcp_Connection_Information_Table #rule 3
        global modbus_tcp_function_list #rule 4 #判斷封包的功能是否一樣
        global modbus_tcp_function_data_list #rule 5 #判斷封包的值是否超過範圍
        global Factory_Block_Table #是否允許將ip阻擋
        if len(Modbus_Tcp_Packet_In_Information_Table)>0:
            for i in range(len(Modbus_Tcp_Packet_In_Information_Table)):
                if Modbus_Tcp_Packet_In_Information_Table[i]['Src_Address']==before_ip:
                    Modbus_Tcp_Packet_In_Information_Table[i]['Src_Address']=after_ip
                if Modbus_Tcp_Packet_In_Information_Table[i]['Dst_Address']==before_ip:
                    Modbus_Tcp_Packet_In_Information_Table[i]['Dst_Address']=after_ip
            self.write_log_object.write_log_txt('Set_change_Device_Information_Modbus_Tcp_Packet_In_Information_Table='+str(Modbus_Tcp_Packet_In_Information_Table))
        if len(Modbus_Tcp_Syn_Information_Table)>0:
            for i in range(len(Modbus_Tcp_Syn_Information_Table)):
                if Modbus_Tcp_Syn_Information_Table[i]['Src_Address']==before_ip:
                    Modbus_Tcp_Syn_Information_Table[i]['Src_Address']=after_ip
                if Modbus_Tcp_Syn_Information_Table[i]['Dst_Address']==before_ip:
                    Modbus_Tcp_Syn_Information_Table[i]['Dst_Address']=after_ip
            self.write_log_object.write_log_txt('Set_change_Device_Information_Modbus_Tcp_Syn_Information_Table='+str(Modbus_Tcp_Syn_Information_Table))
        if len(Modbus_Tcp_Connection_Information_Table)>0:
            for i in range(len(Modbus_Tcp_Connection_Information_Table)):
                if Modbus_Tcp_Connection_Information_Table[i]['Src_Address']==before_ip:
                    Modbus_Tcp_Connection_Information_Table[i]['Src_Address']=after_ip
                if Modbus_Tcp_Connection_Information_Table[i]['Dst_Address']==before_ip:
                    Modbus_Tcp_Connection_Information_Table[i]['Dst_Address']=after_ip
            self.write_log_object.write_log_txt('Set_change_Device_Information_Modbus_Tcp_Connection_Information_Table='+str(Modbus_Tcp_Connection_Information_Table))
        if len(modbus_tcp_function_list)>0:
            for i in range(len(modbus_tcp_function_list)):
                if modbus_tcp_function_list[i]['Src_Address']==before_ip:
                    modbus_tcp_function_list[i]['Src_Address']=after_ip
            self.write_log_object.write_log_txt('Set_change_Device_Information_modbus_tcp_function_list='+str(modbus_tcp_function_list))
        if len(modbus_tcp_function_data_list)>0:
            for i in range(len(modbus_tcp_function_data_list)):
                if modbus_tcp_function_data_list[i]['Src_Address']==before_ip:
                    modbus_tcp_function_data_list[i]['Src_Address']=after_ip
                if modbus_tcp_function_data_list[i]['Dst_Address']==before_ip:
                    modbus_tcp_function_data_list[i]['Dst_Address']=after_ip
            self.write_log_object.write_log_txt('Set_change_Device_Information_modbus_tcp_function_data_list='+str(modbus_tcp_function_data_list))
        if len(Factory_Block_Table)>0:
            for i in range(len(Factory_Block_Table)):
                if Factory_Block_Table[i]['Src_Address']==before_ip:
                    Factory_Block_Table[i]['Src_Address']=after_ip
            self.write_log_object.write_log_txt('Set_change_Device_Information_Factory_Block_Table='+str(Factory_Block_Table))

    def add_Factory_Block_Table(self,ip_address):
        if len(Factory_Block_Table)>0:
            a=[temp for temp in Factory_Block_Table if temp['Src_Address']==ip_address]
            if len(a)<=0:
                self.temp={}
                self.temp['datapath']=None
                self.temp['dpid']=0
                self.temp['Src_Address']=ip_address
                self.temp['block_state']='False'
                Factory_Block_Table.append(self.temp)
            self.write_log_object.write_log_txt('add_Factory_Block_Table='+str(Factory_Block_Table))
    
    def del_Factory_Block_Table(self,ip_address):
        if len(Factory_Block_Table)>0:
            a=[temp for temp in Factory_Block_Table if temp['Src_Address']==ip_address]
            if len(a)>0:
               for i in range(len(Factory_Block_Table)):
                if Factory_Block_Table[i]['Src_Address']==ip_address:
                    del Factory_Block_Table[i]
            self.write_log_object.write_log_txt('del_Factory_Block_Table='+str(Factory_Block_Table))


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        global SCADA_Information_List
        global first_switch_features
        # 一開始 Switch 連上 Controller 時的初始設定 Function
        datapath = ev.msg.datapath # 接收 OpenFlow 交換器實例
        ofproto = datapath.ofproto  # OpenFlow 交換器使用的 OF 協定版本
        parser = datapath.ofproto_parser # 處理 OF 協定的 parser
        self.temp={}
        self.temp['datapath']=datapath
        first_switch_features.append(self.temp)
        del self.temp
        self.write_log_object.write_log_txt('first_switch_features='+str(first_switch_features))

        #--------新增一筆所有封包當阻擋的flow -------------#
        start_default_match = parser.OFPMatch()
        start_default_actions=[]
        self.add_flow(datapath,0,65535,start_default_match,0,start_default_actions)

        
        # t=threading.Thread(target=self.Load_SCADA_Information) #讀取 Device_Information.json，如果有做更改並在全域提醒
        # t.start()
        # self.Set_Device_Information_List()
        # self.write_log_object.write_log_txt('SCADA_Information_List='+str(SCADA_Information_List))


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

        #-----------政策(Policy)_1 (先將有送往PLC的封包送往 Packet_in)-------------------------------------------#
        if len(SCADA_Information_List['PLC_Device'])>0:
            for i in range(len(SCADA_Information_List['PLC_Device'])):
                self.priority=10
                self.table_0_match_1= parser.OFPMatch(eth_type=0x0800,ipv4_dst=SCADA_Information_List['PLC_Device'][i]['IP'])
                self.table_0_inst_rule_1= [parser.OFPInstructionGotoTable(RULE_1_TABLE)] #Go to The Table 1
                self.add_flow(datapath,0, self.priority, self.table_0_match_1, self.table_0_inst_rule_1,state='rule') #在table 0比對到 往table 1送
                self.Record_set_flow_entry(datapath,0,self.priority,0,SCADA_Information_List['PLC_Device'][i]['IP'],inst=self.table_0_inst_rule_1) #rule 0
                self.table_0_match_1= parser.OFPMatch(eth_type=0x0800,ipv4_src=SCADA_Information_List['PLC_Device'][i]['IP'])
                self.add_flow(datapath,0, self.priority, self.table_0_match_1, self.table_0_inst_rule_1,state='rule') #在table 0比對到 往table 1送
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                            ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath,RULE_1_TABLE, 0, match,0, actions)
        

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

        # #-------測試2 (測試Table 0 比對到的封包後再到Table 1進行比對[table 1 為如果是TCP 封包的話，就丟棄])-----------------#
        # table_0_match_1 = parser.OFPMatch(eth_type=0x0800,ipv4_src="192.168.3.40")#比對封包ip 往PLC的
        # table_0_match_2 = parser.OFPMatch(eth_type=0x0800,ipv4_dst="192.168.3.40")#比對ip往PLC的
        # table_0_inst_rule_1= [parser.OFPInstructionGotoTable(RULE_1_TABLE)] #Go to The Table 1
        # self.add_flow(datapath,0, 10, table_0_match_1, table_0_inst_rule_1) #在table 0比對到 往table 1送
        # self.add_flow(datapath,0, 10, table_0_match_2, table_0_inst_rule_1) #在table 0比對到 往table 1送

        # table_1_match_1 = parser.OFPMatch(eth_type=0x0800,ip_proto=0x6)#如果是TCP的話
        # table_1_actions_1 = []                                      
        # self.add_flow(datapath,RULE_1_TABLE, 2, table_1_match_1,0,table_1_actions_1) #在table 0比對到 往table 1送
        
        # table_1_match_0 = parser.OFPMatch() #Table_1如果都沒有 match的話就送往Controller
        # table_1_actions_0 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                   ofproto.OFPCML_NO_BUFFER)]
        # self.add_flow(datapath,RULE_1_TABLE, 0, table_1_match_0,0, table_1_actions_0)
        
        #移除 一開始新增的 所有封包當阻擋的flow
        match = parser.OFPMatch()
        self.delete_flow(datapath,0,65535,match,0)
        print('tempp')



    def add_flow(self, datapath,table_id, priority, match, inst=0, actions=None,state=None):
        global flow_entry_list
        global temp_flow_entry_list  
        # 取得與 Switch 使用的 IF 版本 對應的 OF 協定及 parser
        ofproto = datapath.ofproto
        # print('type datapath='+str(type(datapath)))
        # print(repr(datapath))
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
                                     
        flow_entry_list.append(str(mod))
        if len(flow_entry_list)>0 :
            temp=[]
            for element in flow_entry_list:
                if element not in temp:
                    temp.append(element)
                    # print('add_flow='+str(mod))
                    datapath.send_msg(mod)# 把定義好的 FlowEntry 送給 Switch
            flow_entry_list=temp
            self.write_log_object.write_log_txt('add_flow='+str(temp))

        if state=='rule':
            temp_flow_entry_list.append(str(mod))
            temp=[]
            for element in temp_flow_entry_list:
                if element not in temp:
                    temp.append(element)
            temp_flow_entry_list=temp
            self.write_log_object.write_log_txt('add_flow(rule)='+str(temp_flow_entry_list))
    # def get_all_flow(self):
    #     temp
        
        
    def delete_flow(self,datapath,table_id, priority, match, inst=0, actions=None): #刪除Flow (可以查看[1]的參考網址)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.write_log_object.write_log_txt("delete_flow="+str(match))
        # if inst==0:
        #     inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
        #                                          actions)]
        # else:
        #     inst=inst

        # 刪除FLOW 。 ofproto.OFPFC_DELETE_STRICT 為匹配(match與priority)到政策(Policy)_後，進行刪除
        mod=parser.OFPFlowMod(cookie=0x01,datapath=datapath, table_id=table_id,command=ofproto.OFPFC_DELETE_STRICT,
                              out_port=ofproto.OFPP_ANY,out_group=ofproto.OFPG_ANY,
                              priority=priority,match=match)
        result=datapath.send_msg(mod)
    def default_match_flow(self,datapath,ofproto,parser,table_id):
        # 首先新增一個空的 match，也就是能夠 match 任何封包的 match rule
        match = parser.OFPMatch()
        # 指定這一條 Table-Miss FlowEntry 的對應行為
        # 把所有不知道如何處理的封包都送到 Controller
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # 把 Table-Miss FlowEntry 設定至 Switch，並指定優先權為 0 (最低)
        self.add_flow(datapath,table_id, 0, match,0, actions)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global Modbus_Tcp_Packet_In_Information_Table
        global Modbus_Tcp_Connection_Information_Table
        global Modbus_Tcp_Syn_Information_Table
        global Factory_Block_Table
        global Device_IP_List
        global rule_table_2_set_list
        global rule_2_full_state
        global modbus_tcp_function_list
        global modbus_tcp_function_data_list
        global rule_3_set_state_list

        self.packet_timestamp=getattr(ev, 'timestamp', None) #取得 ev 裡面的 timestamp 。getattr 『取得』class 內定義變數的值
        # print('with timestamp= '+str(self.packet_timestamp))
        self.packet_datetime=self.datetime_object.get_datetime(self.packet_timestamp)
        # print('packet_datetime= '+str(self.packet_datetime))

        msg = ev.msg
        # self.write_log_object.write_log_txt("ev.msg="+str(msg))
        datapath = msg.datapath
        self.write_log_object.write_log_txt('datapath='+str(datapath))
        dpid = datapath.id # Switch 的 datapath id (獨一無二的 ID)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        self.table_id=msg.table_id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        # ------- 測試 ---------------------------#
        print('packet in is table_id='+str(self.table_id))
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

        #將資料寫到log檔
        if pkt.get_protocols(tcp.tcp):
            self.write_log_object.write_log_txt("-----------------")
            self.write_log_object.write_log_txt("ev="+str(ev))
            self.write_log_object.write_log_txt("ev.msg="+str(msg))
            self.write_log_object.write_log_txt("packet in is table_id="+str(self.table_id))
            self.write_log_object.write_log_txt("packet_timestamp="+str(self.packet_timestamp))
            self.write_log_object.write_log_txt("packet_datetime="+str(self.packet_datetime))
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




        # if pkt.get_protocols(tcp.tcp):
        #     print("tcp="+str(self.tcp))
        #     print("tcp_seq_number="+str(self.tcp_seq_number))
        #--政策(Policy)_1-----------------------------------------------------#
        if pkt.get_protocols(ipv4.ipv4) and (self.table_id==RULE_1_TABLE or self.table_id==RULE_2_TABLE):
            self.temp={}
            self.temp2={}
            self.temp3={}
            self.temp['datapath']=datapath
            self.temp['dpid']=dpid
            self.temp['Src_Address']=self.ipv4_src
            self.temp['Dst_Address']=self.ipv4_dst
            self.temp['In_Port']=in_port
            self.temp2['datapath']=datapath
            self.temp2['dpid']=dpid
            self.temp2['Src_Address']=self.ipv4_src
            self.temp2['block_state']='False'
            self.temp3['datapath']=datapath
            self.temp3['dpid']=dpid
            self.temp3['Src_Address']=self.ipv4_dst
            self.temp3['block_state']='False'
            if len(Modbus_Tcp_Packet_In_Information_Table)>0:
                a=[temp for temp in Modbus_Tcp_Packet_In_Information_Table if temp['Src_Address']==self.ipv4_src and temp['Dst_Address']==self.ipv4_dst ] #搜尋是否有在 Modbus_Tcp_Packet_In_Information_Table裡面
                if len(a)>0:
                    for i in range(len(Modbus_Tcp_Packet_In_Information_Table)):
                        if Modbus_Tcp_Packet_In_Information_Table[i]['Src_Address']==self.ipv4_src and Modbus_Tcp_Packet_In_Information_Table[i]['Dst_Address']==self.ipv4_dst:
                            Modbus_Tcp_Packet_In_Information_Table[i]['In_Port']=in_port
                else:#沒有在Table裡面，就新增一筆
                    Modbus_Tcp_Packet_In_Information_Table.append(self.temp)
                    #
                    b=[temp for temp in Factory_Block_Table if temp['Src_Address']==self.ipv4_src] #搜尋是否有在 Factory_Block_Table 裡面
                    if len(b)<=0:
                        Factory_Block_Table.append(self.temp2)

                    c=[temp for temp in Factory_Block_Table if temp['Src_Address']==self.ipv4_dst] #搜尋是否有在 Factory_Block_Table 裡面
                    if len(c)<=0:
                        Factory_Block_Table.append(self.temp3)
            else:
                Modbus_Tcp_Packet_In_Information_Table.append(self.temp)
                Factory_Block_Table.append(self.temp2)
                Factory_Block_Table.append(self.temp3)

            print('----------Rule information------------')
            self.write_log_object.write_log_txt('----------Rule information------------')
            print('Modbus_Tcp_Packet_In_Information_Table= '+str(Modbus_Tcp_Packet_In_Information_Table))
            self.write_log_object.write_log_txt('Modbus_Tcp_Packet_In_Information_Table= '+str(Modbus_Tcp_Packet_In_Information_Table))
            print('Factory_Block_Table= '+str(Factory_Block_Table))
            self.write_log_object.write_log_txt('Factory_Block_Table= '+str(Factory_Block_Table))
        #----- 政策(Policy)_1 判斷進來的封包是否在白名單裡面---------#
        if len(Modbus_Tcp_Packet_In_Information_Table)>0 :
            for i in range(len(Modbus_Tcp_Packet_In_Information_Table)):
                a=[temp for temp in Device_IP_List if temp==Modbus_Tcp_Packet_In_Information_Table[i]['Src_Address'] ] #搜尋是否有在 Modbus_Tcp_Packet_In_Information_Table裡面
                if len(a)<=0:
                    self.priority=20
                    self.table_0_match_1= parser.OFPMatch(eth_type=0x0800,ipv4_src=Modbus_Tcp_Packet_In_Information_Table[i]['Src_Address'])
                    self.table_0_action_1=[]
                    for j in range(len(Factory_Block_Table)):
                        if (Factory_Block_Table[j]['Src_Address']==Modbus_Tcp_Packet_In_Information_Table[i]['Src_Address'])and Factory_Block_Table[j]['block_state']=='False':
                            Factory_Block_Table[j]['block_state']='True'
                            # self.add_flow(datapath,RULE_1_TABLE, self.priority, self.table_0_match_1, 0,self.table_0_action_1,state='rule') #在table 0比對到 往table 1送
                            # self.Record_set_flow_entry(datapath,RULE_1_TABLE,self.priority,1,Modbus_Tcp_Packet_In_Information_Table[i]['Src_Address'],actions=self.table_0_action_1)
                            self.add_flow(datapath,RULE_0_TABLE, self.priority, self.table_0_match_1, 0,self.table_0_action_1,state='rule') #在table 0比對到 往table 1送
                            self.Record_set_flow_entry(datapath,RULE_0_TABLE,self.priority,1,Modbus_Tcp_Packet_In_Information_Table[i]['Src_Address'],actions=self.table_0_action_1)
                            self.write_log_object.write_log_txt('ip_is_block(policy_1)='+str(Modbus_Tcp_Packet_In_Information_Table[i]['Src_Address']))

        #-----------(先將有送往PLC的封包且是TCP的送往 Packet_in)-------------------------------------------#
        if len(SCADA_Information_List['PLC_Device'])>0 and pkt.get_protocols(tcp.tcp) and self.table_id==RULE_1_TABLE:
            # for i in range(len(SCADA_Information_List['PLC_Device'])):
            self.priority=10
            self.table_1_match_1= parser.OFPMatch(eth_type=0x0800,ip_proto=0x6)
            self.table_1_inst_rule_1= [parser.OFPInstructionGotoTable(RULE_2_TABLE)] #Go to The Table 2
            self.add_flow(datapath,RULE_1_TABLE, self.priority, self.table_1_match_1, self.table_1_inst_rule_1) #在table 1比對到 往table 2送
            # match = parser.OFPMatch()
            # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
            #                                 ofproto.OFPCML_NO_BUFFER)]
            # self.add_flow(datapath,RULE_2_TABLE, 0, match,0, actions)
            self.default_match_flow(datapath,ofproto,parser,RULE_2_TABLE)

        if pkt.get_protocols(tcp.tcp) and (self.table_id==RULE_1_TABLE or self.table_id==RULE_2_TABLE):
            if len(Device_IP_List)>0:
                for i in range(len(Device_IP_List)):
                    if self.ipv4_src==Device_IP_List[i] and self.tcp.has_flags(tcp.TCP_SYN):
                        self.ttemp_date_list={}
                        self.ttemp_date_list['Src_Address']=self.ipv4_src
                        self.ttemp_date_list['Dst_Address']=self.ipv4_dst
                        self.ttemp_date_list['Src_Port']=self.tcp_src_port
                        self.ttemp_date_list['Dst_Port']=self.tcp_dst_port
                        self.ttemp_date_list['Syn_Time']=self.packet_timestamp
                        Modbus_Tcp_Syn_Information_Table.append(self.ttemp_date_list)
            # self.write_log_object.write_log_txt('Modbus_Tcp_Syn_Information_Table='+str(Modbus_Tcp_Syn_Information_Table))

            #-----計算syn數量-------------------#
            Modbus_Tcp_Syn_Count_Table=[]
            if len(Modbus_Tcp_Syn_Information_Table)>0:
                for i in range(len(Modbus_Tcp_Syn_Information_Table)):
                    self.temp_data={}
                    if len(Modbus_Tcp_Syn_Count_Table)>0:
                        a=[temp for temp in Modbus_Tcp_Syn_Count_Table if temp['Src_Address']==Modbus_Tcp_Syn_Information_Table[i]['Src_Address'] and temp['Dst_Address']==Modbus_Tcp_Syn_Information_Table[i]['Dst_Address'] and  temp['Src_Port']==Modbus_Tcp_Syn_Information_Table[i]['Src_Port']] #搜尋是否有在 Modbus_Tcp_Connection_Information_Table裡面
                        if len(a)<=0:
                            self.temp_data['Src_Address']=Modbus_Tcp_Syn_Information_Table[i]['Src_Address']
                            self.temp_data['Dst_Address']=Modbus_Tcp_Syn_Information_Table[i]['Dst_Address']
                            self.temp_data['Src_Port']=Modbus_Tcp_Syn_Information_Table[i]['Src_Port']      
                            self.temp_data['Syn_Count']=0
                            Modbus_Tcp_Syn_Count_Table.append(self.temp_data)
                    else:
                        self.temp_data['Src_Address']=Modbus_Tcp_Syn_Information_Table[i]['Src_Address']
                        self.temp_data['Dst_Address']=Modbus_Tcp_Syn_Information_Table[i]['Dst_Address']
                        self.temp_data['Src_Port']=Modbus_Tcp_Syn_Information_Table[i]['Src_Port']
                        self.temp_data['Syn_Count']=0
                        Modbus_Tcp_Syn_Count_Table.append(self.temp_data)
                self.write_log_object.write_log_txt('Modbus_Tcp_Syn_Information_Table='+str(Modbus_Tcp_Syn_Information_Table))
        #----- 政策(Policy)_2 判斷 syn是否超過1次以上-------#
            if len(Modbus_Tcp_Syn_Count_Table)>0:
                for i in range(len(Modbus_Tcp_Syn_Count_Table)):
                    for j in range(len(Modbus_Tcp_Syn_Information_Table)):
                        if Modbus_Tcp_Syn_Count_Table[i]['Src_Address']==Modbus_Tcp_Syn_Information_Table[j]['Src_Address'] and Modbus_Tcp_Syn_Count_Table[i]['Dst_Address']==Modbus_Tcp_Syn_Information_Table[j]['Dst_Address'] and Modbus_Tcp_Syn_Count_Table[i]['Src_Port']==Modbus_Tcp_Syn_Information_Table[j]['Src_Port']:
                            Modbus_Tcp_Syn_Count_Table[i]['Syn_Count']=Modbus_Tcp_Syn_Count_Table[i]['Syn_Count']+1
                        if Modbus_Tcp_Syn_Count_Table[i]['Syn_Count']>2:
                            self.priority=20
                            self.table_1_match_1= parser.OFPMatch(eth_type=0x0800,ipv4_src=Modbus_Tcp_Syn_Count_Table[i]['Src_Address'])
                            self.table_1_actions=[]
                            for k in range(len(Factory_Block_Table)):
                                if (Modbus_Tcp_Syn_Count_Table[i]['Src_Address']==Factory_Block_Table[k]['Src_Address'])and Factory_Block_Table[k]['block_state']=='False':
                                    Factory_Block_Table[k]['block_state']='True'
                                    self.add_flow(datapath,RULE_1_TABLE, self.priority, self.table_1_match_1, 0,self.table_1_actions,state='rule') #在table 2比對到 往table 2送
                                    self.Record_set_flow_entry(datapath,RULE_1_TABLE,self.priority,2,Modbus_Tcp_Syn_Count_Table[i]['Src_Address'],actions=self.table_1_actions)
                                    self.write_log_object.write_log_txt('ip_is_block(policy_2)='+str(Modbus_Tcp_Syn_Count_Table[i]['Src_Address']))
                                    

                self.write_log_object.write_log_txt('Modbus_Tcp_Syn_Count_Table='+str(Modbus_Tcp_Syn_Count_Table))


         #--政策(Policy)_3 前資料儲存----------------------------------------------------------#
        if pkt.get_protocols(tcp.tcp) and self.table_id==RULE_2_TABLE:
            if len(SCADA_Information_List['PLC_Device'])>0:
                for i in range(len(SCADA_Information_List['PLC_Device'])):
                    if self.ipv4_src==SCADA_Information_List['PLC_Device'][i]['IP']:
                        for j in range(len(SCADA_Information_List['PLC_Device'][i]['Port'])):
                            if self.tcp_src_port==SCADA_Information_List['PLC_Device'][i]['Port'][j] and self.tcp.has_flags(tcp.TCP_SYN,tcp.TCP_ACK):
                                self.temp_date_list={}
                                self.temp_date_list['datapath']=datapath
                                self.temp_date_list['dpid']=dpid
                                self.temp_date_list['Src_Address']=self.ipv4_dst
                                self.temp_date_list['Dst_Address']=self.ipv4_src
                                self.temp_date_list['Src_Port']=self.tcp_dst_port
                                self.temp_date_list['Dst_Port']=self.tcp_src_port
                                self.temp_date_list['Syn_Time']=self.packet_timestamp
                                Modbus_Tcp_Connection_Information_Table.append(self.temp_date_list)
                                self.temp_date_list['Set_flow_stat']='False'
                                if rule_table_2_set_list!=Modbus_Tcp_Connection_Information_Table:
                                    rule_table_2_set_list.append(self.temp_date_list)
                                self.write_log_object.write_log_txt("Modbus_Tcp_Connection_Information_Table(syn、ack)="+str(Modbus_Tcp_Connection_Information_Table))
                                self.write_log_object.write_log_txt("rule_table_2_set_list_before="+str(rule_table_2_set_list))
                            elif self.tcp_src_port==SCADA_Information_List['PLC_Device'][i]['Port'][j] and self.tcp.has_flags(tcp.TCP_FIN,tcp.TCP_ACK):
                                if len(Modbus_Tcp_Connection_Information_Table)>0:
                                    Modbus_Tcp_Connection_Information_Table_len=len(Modbus_Tcp_Connection_Information_Table)
                                    for k in range(Modbus_Tcp_Connection_Information_Table_len):
                                        if Modbus_Tcp_Connection_Information_Table[k]['Src_Address']==self.ipv4_dst and Modbus_Tcp_Connection_Information_Table[k]['Dst_Address']==self.ipv4_src and Modbus_Tcp_Connection_Information_Table[k]['Src_Port']==self.tcp_dst_port and Modbus_Tcp_Connection_Information_Table[k]['Dst_Port']==self.tcp_src_port:
                                            Modbus_Tcp_Connection_Information_Table[k]['Fin_Time']=self.packet_timestamp
                                            Modbus_Tcp_Connection_Information_Table[k]['Duration_Time']=Modbus_Tcp_Connection_Information_Table[k]['Fin_Time']-Modbus_Tcp_Connection_Information_Table[k]['Syn_Time']
                                    self.write_log_object.write_log_txt("Modbus_Tcp_Connection_Information_Table(fin、ack)="+str(Modbus_Tcp_Connection_Information_Table))
        
        #------------------------------------------------------------------------#
        #-------- 計算 tcp connect ip 數量----------------------------#
        Modbus_Tcp_Connect_Count_Table=[]
        if len(Modbus_Tcp_Connection_Information_Table)>0:
            for i in range(len(Modbus_Tcp_Connection_Information_Table)):
                self.temp_data={}
                if len(Modbus_Tcp_Connect_Count_Table)>0:
                    a=[temp for temp in Modbus_Tcp_Connect_Count_Table if temp['Src_Address']==Modbus_Tcp_Connection_Information_Table[i]['Src_Address'] and temp['Dst_Address']==Modbus_Tcp_Connection_Information_Table[i]['Dst_Address'] ] #搜尋是否有在 Modbus_Tcp_Connection_Information_Table裡面
                    if len(a)<=0:
                        self.temp_data['Src_Address']=Modbus_Tcp_Connection_Information_Table[i]['Src_Address']
                        self.temp_data['Dst_Address']=Modbus_Tcp_Connection_Information_Table[i]['Dst_Address']        
                        self.temp_data['Connect_Count']=0
                        Modbus_Tcp_Connect_Count_Table.append(self.temp_data)
                else:
                    self.temp_data['Src_Address']=Modbus_Tcp_Connection_Information_Table[i]['Src_Address']
                    self.temp_data['Dst_Address']=Modbus_Tcp_Connection_Information_Table[i]['Dst_Address']
                    self.temp_data['Connect_Count']=0
                    Modbus_Tcp_Connect_Count_Table.append(self.temp_data)
            if len(Modbus_Tcp_Connect_Count_Table)>0:
                for i in range(len(Modbus_Tcp_Connect_Count_Table)):
                    for j in range(len(Modbus_Tcp_Connection_Information_Table)):
                        if Modbus_Tcp_Connect_Count_Table[i]['Src_Address']==Modbus_Tcp_Connection_Information_Table[j]['Src_Address'] and Modbus_Tcp_Connect_Count_Table[i]['Dst_Address']==Modbus_Tcp_Connection_Information_Table[j]['Dst_Address']:
                            Modbus_Tcp_Connect_Count_Table[i]['Connect_Count']=Modbus_Tcp_Connect_Count_Table[i]['Connect_Count']+1

            # print('Modbus_Tcp_Connect_Count_Table='+str(Modbus_Tcp_Connect_Count_Table))
            self.write_log_object.write_log_txt('Modbus_Tcp_Connect_Count_Table='+str(Modbus_Tcp_Connect_Count_Table))
        
        #------------- 政策(Policy)_3  判斷 使用 tcp connect ip 數量 去阻擋------------------------#
        if len(Modbus_Tcp_Connect_Count_Table)>0:
            for i in range(len(Modbus_Tcp_Connect_Count_Table)):
                if (Modbus_Tcp_Connect_Count_Table[i]['Connect_Count']<=SCADA_Information_List['PLC_Allow_Connect_number'])and rule_table_2_set_list[i]['Set_flow_stat']=='False':
                    for j in range(len(Modbus_Tcp_Connection_Information_Table)):
                        # if Modbus_Tcp_Connect_Count_Table[i]['Src_Address']==Modbus_Tcp_Connection_Information_Table[j]['Src_Address'] and Modbus_Tcp_Connect_Count_Table[i]['Dst_Address']==Modbus_Tcp_Connection_Information_Table[j]['Dst_Address'] and Modbus_Tcp_Connect_Count_Table[i]['Src_Port']==Modbus_Tcp_Connection_Information_Table[j]['Src_Port'] and Modbus_Tcp_Connect_Count_Table[i]['Dst_Port']==Modbus_Tcp_Connection_Information_Table[j]['Dst_Port']:
                        if Modbus_Tcp_Connect_Count_Table[i]['Src_Address']==Modbus_Tcp_Connection_Information_Table[j]['Src_Address'] and Modbus_Tcp_Connect_Count_Table[i]['Dst_Address']==Modbus_Tcp_Connection_Information_Table[j]['Dst_Address'] and rule_table_2_set_list[i]['Set_flow_stat']=='False' :
                            self.priority=10
                            self.table_2_match_1= parser.OFPMatch(eth_type=0x0800,ip_proto=0x6,ipv4_src=Modbus_Tcp_Connection_Information_Table[i]['Src_Address'],ipv4_dst=Modbus_Tcp_Connection_Information_Table[i]['Dst_Address'])
                            self.table_2_match_2= parser.OFPMatch(eth_type=0x0800,ip_proto=0x6,ipv4_src=Modbus_Tcp_Connection_Information_Table[i]['Dst_Address'],ipv4_dst=Modbus_Tcp_Connection_Information_Table[i]['Src_Address'])
                            self.table_2_inst_rule_1= [parser.OFPInstructionGotoTable(RULE_3_TABLE)] #Go to The Table 3
                            self.add_flow(datapath,RULE_2_TABLE, self.priority, self.table_2_match_1, self.table_2_inst_rule_1,state='rule') #在table 2比對到 往table 3送
                            self.add_flow(datapath,RULE_2_TABLE, self.priority, self.table_2_match_2, self.table_2_inst_rule_1,state='rule') #在table 2比對到 往table 3送
                            self.Record_set_flow_entry(datapath,RULE_2_TABLE,self.priority,3,Modbus_Tcp_Connection_Information_Table[i]['Src_Address'],Modbus_Tcp_Connection_Information_Table[i]['Dst_Address'],inst=self.table_2_inst_rule_1)
                            self.default_match_flow(datapath,ofproto,parser,RULE_3_TABLE)
                            rule_table_2_set_list[i]['Set_flow_stat']='True'
                            self.write_log_object.write_log_txt("rule_table_2_set_list_after="+str(rule_table_2_set_list))
                            self.temp={}
                            self.temp['datapath']=datapath
                            self.temp['dpid']=dpid
                            self.temp['rule_3_set_all_packet_block']='False'
                            if len(rule_3_set_state_list)>0:
                                a=[temp for temp in rule_3_set_state_list['datapath'] if temp==datapath]
                                if len(a)<=0:
                                    rule_3_set_state_list.append(self.temp)    
                            else:
                                rule_3_set_state_list.append(self.temp)
                            self.write_log_object.write_log_txt("rule_3_set_state_list="+str(rule_3_set_state_list))
            if len(rule_3_set_state_list)>0:
                for k in range(len(rule_3_set_state_list)):
                    if (len(Modbus_Tcp_Connect_Count_Table)>=SCADA_Information_List['PLC_Allow_Connect_number']) and (rule_3_set_state_list[k]['datapath']==datapath) and rule_3_set_state_list[k]['rule_3_set_all_packet_block']=='False':
                        self.priority=5
                        self.table_2_match_3= parser.OFPMatch()
                        self.table_2_action_3=[]
                        self.add_flow(datapath,RULE_2_TABLE, self.priority, self.table_2_match_3,0,self.table_2_action_3) #比對不到的全部丟掉
                        rule_3_set_state_list[k]['rule_3_set_all_packet_block']='True'
                    
        #-----------------計算modbus tcp 封包是否請求一樣(政策(Policy)_4)--------------------------#
        if pkt.get_protocols(tcp.tcp) and pkt.__len__()==4 and self.tcp.has_flags(tcp.TCP_PSH,tcp.TCP_ACK) and (self.table_id==RULE_2_TABLE or self.table_id==RULE_3_TABLE) :
            mb=modbus_tcp.modbus_tcp()
            mb.get_modbus_tcp(self.tcp_src_port,self.tcp_dst_port,pkt.__getitem__(3))
            self.write_log_object.write_log_txt("****************")
            self.write_log_object.write_log_txt("mb.t_id="+str(mb.t_id))
            self.write_log_object.write_log_txt("mb.p_id="+str(mb.p_id))
            self.write_log_object.write_log_txt("mb.modbus_len="+str(mb.modbus_len))
            self.write_log_object.write_log_txt("mb.u_id="+str(mb.u_id))
            for i in range(len(SCADA_Information_List['PLC_Device'])): 
                for j in range(len(SCADA_Information_List['PLC_Device'][i]['Port'])):
                    if self.ipv4_dst==SCADA_Information_List['PLC_Device'][i]['IP'] and self.tcp_dst_port==SCADA_Information_List['PLC_Device'][i]['Port'][j]: #request
                        print("*****request <<<<< *****")
                        print("mb.fun_code="+str(mb.fun_code))
                        self.write_log_object.write_log_txt("*****request <<<<< *****")
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
                        #---政策(Policy)_4 前資料儲存-------------------------------------------#
                        self.temp={}
                        self.temp['Src_Address']=self.ipv4_src
                        self.temp['function_code']=[]
                        self.temp['function_code'].append(mb.fun_code)
                        if len(modbus_tcp_function_list)>0:
                            a=[temp for temp in modbus_tcp_function_list if temp['Src_Address']==self.ipv4_src] #搜尋是否有在 Modbus_Tcp_Packet_In_Information_Table裡面
                            if len(a)>0:
                                for k in range(len(modbus_tcp_function_list)):
                                    if self.ipv4_src==modbus_tcp_function_list[k]['Src_Address']:
                                        modbus_tcp_function_list[k]['function_code'].append(mb.fun_code)
                            else:
                                modbus_tcp_function_list.append(self.temp) 
                        else:
                            modbus_tcp_function_list.append(self.temp)
                        self.write_log_object.write_log_txt('modbus_tcp_function_list_before='+str(modbus_tcp_function_list))
                        #---政策(Policy)_5 前資料儲存-------------------------------------------#
                        self.tempp={}
                        self.tempp['Src_Address']=self.ipv4_src
                        self.tempp['Dst_Address']=self.ipv4_dst
                        self.tempp['function_code']=mb.fun_code
                        self.tempp['reference_num']=mb.reference_number
                        self.tempp['bit_count']=mb.Bit_Count
                        if len(modbus_tcp_function_data_list)>0:
                            a=[temp for temp in modbus_tcp_function_data_list if temp['Src_Address']==self.ipv4_src and temp['Dst_Address']==self.ipv4_dst] #搜尋是否有在 Modbus_Tcp_Packet_In_Information_Table裡面
                            if len(a)>0:
                                for k in range(len(modbus_tcp_function_data_list)):
                                    if self.ipv4_src==modbus_tcp_function_data_list[k]['Src_Address'] and self.ipv4_dst==modbus_tcp_function_data_list[k]['Dst_Address']:
                                        modbus_tcp_function_data_list[k]['function_code']=mb.fun_code
                                        modbus_tcp_function_data_list[k]['reference_num']=mb.reference_number
                                        modbus_tcp_function_data_list[k]['bit_count']=mb.Bit_Count
                            else:
                                modbus_tcp_function_data_list.append(self.tempp) 
                        else:
                            modbus_tcp_function_data_list.append(self.tempp)
                        self.write_log_object.write_log_txt('modbus_tcp_function_data_list='+str(modbus_tcp_function_data_list))
                    elif self.ipv4_src==SCADA_Information_List['PLC_Device'][i]['IP'] and self.tcp_src_port==SCADA_Information_List['PLC_Device'][i]['Port'][j]: #request
                        print("*****response >>>> *****")
                        print("mb.fun_code="+str(mb.fun_code))
                        self.write_log_object.write_log_txt("*****response >>>> *****")
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
        #-----政策(Policy)_4 判斷 modbus tcp 重複 查詢是否連續3次以上----------------#      
            if len(modbus_tcp_function_list)>0:
                for i in range(len(modbus_tcp_function_list)):
                    if len(modbus_tcp_function_list[i]['function_code'])==4:
                        self.Moubus_Tcp_Function_Count_Table=Counter(modbus_tcp_function_list[i]['function_code'])
                        for j in range(15):
                            if self.Moubus_Tcp_Function_Count_Table[j]>3:
                                self.priority=20
                                self.table_3_match_1= parser.OFPMatch(eth_type=0x0800,ipv4_src=modbus_tcp_function_list[i]['Src_Address'])
                                self.table_3_actions=[]
                                for k in range(len(Factory_Block_Table)):
                                    if (modbus_tcp_function_list[i]['Src_Address']==Factory_Block_Table[k]['Src_Address'])and Factory_Block_Table[k]['block_state']=='False':
                                        Factory_Block_Table[k]['block_state']='True'
                                        self.add_flow(datapath,RULE_3_TABLE, self.priority, self.table_3_match_1, 0,self.table_3_actions,state='rule') #在table 2比對到 往table 2送
                                        self.Record_set_flow_entry(datapath,RULE_3_TABLE,self.priority,4,modbus_tcp_function_list[i]['Src_Address'],actions=self.table_3_actions)
                                        self.write_log_object.write_log_txt('ip_is_block(policy_4)='+str(modbus_tcp_function_list[i]['Src_Address']))
                                                        
                        modbus_tcp_function_list[i]['function_code']=[]
                self.write_log_object.write_log_txt('modbus_tcp_function_list_after='+str(modbus_tcp_function_list))
        #----- 政策(Policy)_5 判斷modbus tcp 資料是否超過 範圍---------------------#
            if len(modbus_tcp_function_data_list)>0:
                for i in range(len(modbus_tcp_function_data_list)):
                    for j in range(len(SCADA_Information_List['PLC_Device'])):
                        if  modbus_tcp_function_data_list[i]['Dst_Address']==SCADA_Information_List['PLC_Device'][j]['IP']:
                            for k in range(len(SCADA_Information_List['PLC_Device'][j]['PLC_Device_GPIO_Open_State'])):
                                if modbus_tcp_function_data_list[i]['function_code']==SCADA_Information_List['PLC_Device'][j]['PLC_Device_GPIO_Open_State'][k]['model'] and modbus_tcp_function_data_list[i]['reference_num']==SCADA_Information_List['PLC_Device'][j]['PLC_Device_GPIO_Open_State'][k]['Start'] and modbus_tcp_function_data_list[i]['bit_count']==SCADA_Information_List['PLC_Device'][j]['PLC_Device_GPIO_Open_State'][k]['Range']:
                                    print('Coil ok range')
                                    self.write_log_object.write_log_txt('Coil ok range')
                                    break
                                elif modbus_tcp_function_data_list[i]['function_code']==5 and SCADA_Information_List['PLC_Device'][j]['PLC_Device_GPIO_Open_State'][k]['model']==1 : #還未寫
                                    if modbus_tcp_function_data_list[i]['reference_num'] >=SCADA_Information_List['PLC_Device'][j]['PLC_Device_GPIO_Open_State'][k]['Start'] or modbus_tcp_function_data_list[i]['reference_num'] <=SCADA_Information_List['PLC_Device'][j]['PLC_Device_GPIO_Open_State'][k]['End']:
                                        print('write Coil ok range')
                                        self.write_log_object.write_log_txt('write Coil ok range')
                                        break

                                if k==3:
                                    self.priority=20
                                    self.table_3_match_2= parser.OFPMatch(eth_type=0x0800,ipv4_src=modbus_tcp_function_data_list[i]['Src_Address'])
                                    self.table_3_actions=[]
                                    for k in range(len(Factory_Block_Table)):
                                        if (modbus_tcp_function_data_list[i]['Src_Address']==Factory_Block_Table[k]['Src_Address'])and Factory_Block_Table[k]['block_state']=='False':
                                            Factory_Block_Table[k]['block_state']='True'
                                            self.add_flow(datapath,RULE_3_TABLE, self.priority, self.table_3_match_2, 0,self.table_3_actions,state='rule') #在table 2比對到 往table 2送
                                            self.Record_set_flow_entry(datapath,RULE_3_TABLE,self.priority,5,modbus_tcp_function_data_list[i]['Src_Address'],actions=self.table_3_actions)
                                            self.write_log_object.write_log_txt('ip_is_block(policy_5)='+str(modbus_tcp_function_data_list[i]['Src_Address']))
                                    print('not ok range')
                                    self.write_log_object.write_log_txt('not ok range')

        # -------- END ------------------------#
        
        dpid = datapath.id # Switch 的 datapath id (獨一無二的 ID)
        self.write_log_object.write_log_txt('dpid='+str(dpid))
        print('dpid='+str(dpid))
        # 如果 MAC 表內不曾儲存過這個 Switch 的 MAC，則幫他新增一個預設值
        # ex. mac_to_port = {'1': {'AA:BB:CC:DD:EE:FF': 2}}
        #     但是目前 dpid 為 2 不存在，執行後 mac_to_port 會變成
        #     mac_to_port = {'1': {'AA:BB:CC:DD:EE:FF': 2}, '2': {}}
        self.mac_to_port.setdefault(dpid, {})
        self.ip_to_port.setdefault(dpid,{})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        # 我們擁有來源端 MAC 與 in_port 了，因此可以學習到 src MAC 要往 in_port 送
        self.mac_to_port[dpid][src] = in_port
        if pkt.get_protocols(ipv4.ipv4):
            self.ipv4=pkt.get_protocols(ipv4.ipv4)[0]
            self.ipv4_src = self.ipv4.src
            self.ipv4_dst = self.ipv4.dst
            self.ip_to_port[dpid][self.ipv4_src]=in_port

        # 如果 目的端 MAC 在 mac_to_port 表中的話，就直接告訴 Switch 送到 out_port
        # 否則就請 Switch 用 Flooding 送出去
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        self.write_log_object.write_log_txt('self.mac_to_port='+str(self.mac_to_port))
        self.write_log_object.write_log_txt('self.ip_to_port='+str(self.ip_to_port))
        # if self.ipv4_dst in self.ip_to_port[dpid]:
        #     out_port = self.mac_to_port[dpid][self.ipv4_dst]

        # 把剛剛的 out_port 作成這次封包的處理動作
        actions = [parser.OFPActionOutput(out_port)]

        # 如果沒有讓 switch flooding，表示目的端 mac 有學習過
        # 因此使用 add_flow 讓 Switch 新增 FlowEntry 學習此筆政策(Policy)_

        # install a flow to avoid packet_in next time
        if self.table_id ==0 and (out_port != ofproto.OFPP_FLOOD ):
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # print("-----------------------aaasss==---------")
            self.add_flow(datapath,0, 1, match,0, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        match = parser.OFPMatch(in_port=in_port)
        # 把要 Switch 執行的動作包裝成 Packet_out，並讓 Switch 執行動作
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  match=match, actions=actions, data=data)
        if len(Factory_Block_Table)>0 and (self.table_id==RULE_1_TABLE or self.table_id==RULE_2_TABLE or self.table_id==RULE_3_TABLE):
            for i in range(len(Factory_Block_Table)):
                if Factory_Block_Table[i]['Src_Address']==self.ipv4_src and Factory_Block_Table[i]['block_state']=='False': #如果封包進來的ip沒有被Factory_Block_Table 註記為阻擋狀態下
                    datapath.send_msg(out) #將封包傳送回ovs
                # elif self.table_id==RULE_2_TABLE:
                #     datapath.send_msg(out) #將封包傳送回ovs
        else:
            datapath.send_msg(out)#將封包傳送回ovs
