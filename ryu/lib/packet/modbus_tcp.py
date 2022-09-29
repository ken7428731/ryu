#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 可參考 這個網站: https://umodbus.readthedocs.io/en/latest/functions.html
# 也可察看這個 https://stackoverflow.com/questions/53065365/how-can-i-send-with-struct-pack-type-over-modbus-tcp
# 

import struct
import os


# path ='/home/mnlab/Desktop/ryu/ryu/app/scada_log/'
# filepath = path+'log/'
# filename= '20220516_log.txt'


class modbus_tcp():
    """
    ============== ====================
    Attribute      Description
    ============== ====================
    tid      
    p_id      
    modbus_len       
    u_id            
    fun_code        
    reference_number    
    modbus_data   
    padding           
    ============== ====================
    """

    # 這邊我拆成兩段
    _PACK_HEADER = '>HHHB'  #header 前贅詞
    _PACK_HEADER_FUN = _PACK_HEADER+'B'
    #--------Modbus Functions----------#
    #--------Read Coils: 01---------#
    _PACK_MODBUS_Read_Coils_Request='HH'
    _PACK_MODBUS_Read_Coils_reponse='BB'
    #--------Read Discrete Inputs: 02---------#
    _PACK_MODBUS_Read_Discrete_Inputs_Request='HH'
    _PACK_MODBUS_Read_Discrete_Inputs_reponse='BB'
    #--------Read Holding Registers: 03---------#
    _PACK_MODBUS_Read_Holding_Registers_Request='HH'
    _PACK_MODBUS_Read_Holding_Registers_reponse='BHHH'
    #--------Read Input Registers: 04---------#
    _PACK_MODBUS_Read_Input_Registers_Request='HH'
    _PACK_MODBUS_Read_Input_Registers_reponse='BHHH'
    #--------Write Single Coil: 05---------#
    _PACK_MODBUS_Write_Single_Coil_Request='HH'
    #--------Write Single Register: 06---------#
    _PACK_MODBUS_Write_Single_Register_Request='HH'
    #--------Write Multiple Coils: 15---------#
    _PACK_MODBUS_Write_Multiple_Coils_Request='HHBB'
    #--------Write Multiple Registers: 16---------#
    _PACK_MODBUS_Write_Multiple_Registers_Request='HHBH'



    # _PACK_STR=_PACK_HEADER+'BHH'
    # _MIN_LEN = struct.calcsize(_PACK_STR) #計算封包結構大小


    def __init__(self):
        self.t_id=0
        self.p_id=0
        self.modbus_len=0
        self.u_id=0
        self.fun_code=None
        self.byte_count=None
        self.reference_number=None
        self.data_lenth=None
        self.modbus_data=[]
        self.Bit_Count=None
        self.modbus_5_data=None

        self.lenn=0
        # self.response_byte_count=0
        self.package_all_len=0
    
    
    # def write_log_txt(self, data):
    #     with open(filepath+filename,'a') as f:
    #         # time.sleep(0.02)
    #         f.write(str(data)+'\n')
    #         f.close()

    def mbap_function_parser(self,buf):
        (self.t_id, self.p_id, self.modbus_len, self.u_id, self.fun_code) = struct.unpack_from(self._PACK_HEADER_FUN, buf)
    def mbap_function_serialize(self):
        return struct.pack(self._PACK_HEADER_FUN,self.t_id, self.p_id, self.modbus_len, self.u_id, self.fun_code)
    # def packet_status(self,buf):

    def coil_address_on(self):
        coils_address_list=[]
        all_len=len(self.modbus_data) #假設是 self.modbus_data=[(2,)] , all_len=1
        temp_len=0
        while temp_len<all_len:
            temp_list=[]
            item = bin(int(self.modbus_data[temp_len][0])) #item= 0b10
            print(item)
            # 去掉每段二进制前的0b.
            item = item[2:] #item=10
            #每个字段转换成八位，不足的在每段前补0.
            temp=item.zfill(8) #temp='00000010'
            # print(temp)
            temp2=''
            for i in range(len(temp)):#反轉
                temp2=temp2+temp[7-i] #temp2='01000000'
            for i in range(len(temp2)):
                if temp2[i]=='1':
                    if temp_len==0:
                        temp_list.append(i+(temp_len))
                    else:    
                        temp_list.append(i+(temp_len*8))
            coils_address_list.append(temp_list)
            temp_len=temp_len+1
        # print('coils_address_list='+str(coils_address_list))
        self.modbus_data=coils_address_list #self.modbus_data=[[1], [8]]

    def pdu_parser(self,src_port,dst_port,buf):
        """
        ============== ====================
        Attribute      Description
        ============== ====================
        src_port       tcp src port
        dst_port       tcp dst port
        buf            modbus
        ============== ====================
        """
        self.package_all_len=struct.calcsize(self._PACK_HEADER_FUN)
        if self.fun_code==1:
            (self.t_id, self.p_id, self.modbus_len, self.u_id, self.fun_code,self.byte_count)=struct.unpack_from(self._PACK_HEADER_FUN+'B',buf)
            self._MIN_LEN=struct.calcsize(self._PACK_HEADER_FUN+'B') #計算封包結構大小
            self.lenn=len(buf[self._MIN_LEN:])
            # print('self.t_id='+str(self.t_id))
            # print('self.p_id='+str(self.p_id))
            # print('self.modbus_len='+str(self.modbus_len))
            # print('self.fun_code='+str(self.fun_code))
            # print('self.byte_count='+str(self.byte_count))
            if (self.byte_count ==self.lenn) and src_port==502:  #response
                self.byte_count=struct.unpack_from('>'+self._PACK_MODBUS_Read_Coils_reponse[0], buf,self._MIN_LEN-1)
                self.next_char_number=self._MIN_LEN
                j=0
                # print('self._MIN_LEN='+str(self._MIN_LEN))
                # print('self.byte_count='+str(self.byte_count))
                # print('self.lenn='+str(self.lenn))
                # print('self.next_char_number='+str(self.next_char_number))
                while self.lenn>0:
                    if j>=len(self._PACK_MODBUS_Read_Coils_reponse):
                        j=(len(self._PACK_MODBUS_Read_Coils_reponse)-1)
                    # print('j='+str(j))
                    # print('self._PACK_MODBUS_Read_Coils_reponse['+str(j)+']='+str(self._PACK_MODBUS_Read_Coils_reponse[j]))
                    # print('self.next_char_number='+str(self.next_char_number))
                    self.char_len=struct.calcsize(self._PACK_MODBUS_Read_Coils_reponse[j])
                    # print('self.char_len='+str(self.char_len))
                    self.modbus_data.append(struct.unpack_from('>'+self._PACK_MODBUS_Read_Coils_reponse[j], buf,self.next_char_number))
                    self.next_char_number=self.next_char_number+self.char_len
                    j=j+1
                    self.lenn=self.lenn-self.char_len
                # print('self.modbus_data='+str(self.modbus_data))
                self.coil_address_on()
            else: #request
                self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Read_Coils_Request[0], buf,self.package_all_len)
                self.char_len=struct.calcsize(self._PACK_MODBUS_Read_Coils_Request[1])
                self.Bit_Count=struct.unpack_from('>'+self._PACK_MODBUS_Read_Coils_Request[1], buf,self.package_all_len+self.char_len)

        elif self.fun_code==2:
            (self.t_id, self.p_id, self.modbus_len, self.u_id, self.fun_code,self.byte_count)=struct.unpack_from(self._PACK_HEADER_FUN+'B',buf)
            self._MIN_LEN=struct.calcsize(self._PACK_HEADER_FUN+'B') #計算封包結構大小
            self.lenn=len(buf[self._MIN_LEN:])
            if (self.byte_count ==self.lenn) and src_port==502 :  #response
                self.byte_count=struct.unpack_from('>'+self._PACK_MODBUS_Read_Discrete_Inputs_reponse[0], buf,self._MIN_LEN-1)
                self.next_char_number=self._MIN_LEN
                j=1
                while self.lenn>0:
                    if j>=len(self._PACK_MODBUS_Read_Discrete_Inputs_reponse):
                        j=(len(self._PACK_MODBUS_Read_Discrete_Inputs_reponse)-1)           
                    self.char_len=struct.calcsize(self._PACK_MODBUS_Read_Discrete_Inputs_reponse[j])
                    self.modbus_data.append(struct.unpack_from('>'+self._PACK_MODBUS_Read_Discrete_Inputs_reponse[j], buf,self.next_char_number))
                    self.next_char_number=self.next_char_number+self.char_len
                    j=j+1
                    self.lenn=self.lenn-self.char_len
            else: #request
                self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Read_Discrete_Inputs_Request[0], buf,self.package_all_len)
                self.char_len=struct.calcsize(self._PACK_MODBUS_Read_Discrete_Inputs_Request[1])
                self.Bit_Count=struct.unpack_from('>'+self._PACK_MODBUS_Read_Discrete_Inputs_Request[1], buf,self.package_all_len+self.char_len)
        elif self.fun_code==3: 
            (self.t_id, self.p_id, self.modbus_len, self.u_id, self.fun_code,self.byte_count)=struct.unpack_from(self._PACK_HEADER_FUN+'B',buf)
            self._MIN_LEN=struct.calcsize(self._PACK_HEADER_FUN+'B') #計算封包結構大小
            self.lenn=len(buf[self._MIN_LEN:])
            if (self.byte_count ==self.lenn) and src_port==502:  #response
                self.byte_count=struct.unpack_from('>'+self._PACK_MODBUS_Read_Holding_Registers_reponse[0], buf,self._MIN_LEN-1)
                self.next_char_number=self._MIN_LEN
                j=1
                while self.lenn>0:
                    if j>=len(self._PACK_MODBUS_Read_Holding_Registers_reponse):
                        j=(len(self._PACK_MODBUS_Read_Holding_Registers_reponse)-1)                   
                    self.char_len=struct.calcsize(self._PACK_MODBUS_Read_Holding_Registers_reponse[j])
                    self.modbus_data.append(struct.unpack_from('>'+self._PACK_MODBUS_Read_Holding_Registers_reponse[j], buf,self.next_char_number))
                    self.next_char_number=self.next_char_number+self.char_len
                    j=j+1
                    self.lenn=self.lenn-self.char_len        
            else: #request
                self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Read_Holding_Registers_Request[0], buf,self.package_all_len)
                self.char_len=struct.calcsize(self._PACK_MODBUS_Read_Holding_Registers_Request[1])
                self.Bit_Count=struct.unpack_from('>'+self._PACK_MODBUS_Read_Holding_Registers_Request[1], buf,self.package_all_len+self.char_len)
        elif self.fun_code==4:  #未做測試
            (self.t_id, self.p_id, self.modbus_len, self.u_id, self.fun_code,self.byte_count)=struct.unpack_from(self._PACK_HEADER_FUN+'B',buf)
            self._MIN_LEN=struct.calcsize(self._PACK_HEADER_FUN+'B') #計算封包結構大小
            self.lenn=len(buf[self._MIN_LEN:])
            if (self.byte_count ==self.lenn) and src_port==502:  #response
                self.byte_count=struct.unpack_from('>'+self._PACK_MODBUS_Read_Input_Registers_reponse[0], buf,self._MIN_LEN-1)
                self.next_char_number=self._MIN_LEN
                j=1
                while self.lenn>0:                    
                    self.char_len=struct.calcsize(self._PACK_MODBUS_Read_Input_Registers_reponse[j])
                    self.modbus_data.append(struct.unpack_from('>'+self._PACK_MODBUS_Read_Input_Registers_reponse[j], buf,self.next_char_number))
                    self.next_char_number=self.next_char_number+self.char_len
                    j=j+1
                    self.lenn=self.lenn-self.char_len
            else: #request
                self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Read_Input_Registers_Request[0], buf,self.package_all_len)
                self.char_len=struct.calcsize(self._PACK_MODBUS_Read_Input_Registers_Request[1])
                self.Bit_Count=struct.unpack_from('>'+self._PACK_MODBUS_Read_Input_Registers_Request[1], buf,self.package_all_len+self.char_len)
        elif self.fun_code==5:
            self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Write_Single_Coil_Request[0], buf,self.package_all_len)
            self.char_len=struct.calcsize(self._PACK_MODBUS_Write_Single_Coil_Request[1])
            self.modbus_5_data=struct.unpack_from('>'+self._PACK_MODBUS_Write_Single_Coil_Request[1], buf,self.package_all_len+self.char_len)
        elif self.fun_code==6: #不確定
            self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Write_Single_Register_Request[0], buf,self.package_all_len)
            self.char_len=struct.calcsize(self._PACK_MODBUS_Write_Single_Register_Request[1])
            self.Bit_Count=struct.unpack_from('>'+self._PACK_MODBUS_Write_Single_Register_Request[1], buf,self.package_all_len+self.char_len)
        elif self.fun_code==15:
            self._fun_15_LEN=struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request) #計算整個封包結構大小
            self.package_len=len(buf)
            if (self.package_len==self._fun_15_LEN) and src_port==502:
                self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Coils_Request[0],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request[0]))
                self.data_lenth=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Coils_Request[1],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request[1]))
                self.byte_count=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Coils_Request[2],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request[2]))
                self.next_char_number=struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request[2])
                self.lenn=len(buf[self.next_char_number:])
                j=3
                while self.lenn>0:                    
                    self.char_len=struct.calcsize(self._PACK_MODBUS_Write_Multiple_Coils_Request[j])
                    self.modbus_data.append(struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Coils_Request[j], buf,self.next_char_number))
                    self.next_char_number=self.next_char_number+self.char_len
                    self.lenn=self.lenn-self.char_len
            else:
                self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Coils_Request[0],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request[0]))
                self.data_lenth=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Coils_Request[1],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request[1]))
        elif self.fun_code==16:
            self._fun_16_LEN=struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Registers_Request) #計算整個封包結構大小
            self.package_len=len(buf)
            if (self.package_len==self._fun_16_LEN) and src_port==502:
                self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Registers_Request[0],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request[0]))
                self.data_lenth=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Registers_Request[1],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request[1]))
                self.byte_count=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Registers_Request[2],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Coils_Request[2]))
                self.next_char_number=struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Registers_Request[2])
                self.lenn=len(buf[self.next_char_number:])
                j=3
                while self.lenn>0:                    
                    self.char_len=struct.calcsize(self._PACK_MODBUS_Write_Multiple_Registers_Request[j])
                    self.modbus_data.append(struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Registers_Request[j], buf,self.next_char_number))
                    self.next_char_number=self.next_char_number+self.char_len
                    self.lenn=self.lenn-self.char_len
            else:
                self.reference_number=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Registers_Request[0],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Registers_Request[0]))
                self.data_lenth=struct.unpack_from('>'+self._PACK_MODBUS_Write_Multiple_Registers_Request[1],buf,struct.calcsize(self._PACK_HEADER_FUN+self._PACK_MODBUS_Write_Multiple_Registers_Request[1]))           

    

    def get_modbus_tcp(self,src_port,dst_port,buf):
        self.mbap_function_parser(buf)
        self.pdu_parser(src_port,dst_port,buf)
        # return (self.t_id, self.p_id, self.modbus_len, self.u_id, self.fun_code,self.reference_number,self.modbus_data)
    

        

