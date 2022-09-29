#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
path ='/home/mnlab/Desktop/ryu/ryu/app/scada_log/'
filepath = path+'log/'
date_string='20220517_6-4attack'
filename= date_string+'_log.txt'
filename2= date_string+'_log2.txt'
filename3= date_string+'_ovs_flow_port_log.txt'
filename4= date_string+'_ovs_port_log.txt'
class write_log():
    # def __init__(self):
        # self.delete_old_log_file()
    def delete_old_log_file(self):
        os.system('rm -rf '+filepath+filename)
        print('old file log(write_log-filename) is rm')
    def delete_old_log_file_2(self):
        os.system('rm -rf '+filepath+filename2)
        print('old file log(write_log-filename2) is rm')
    def delete_old_log_file_3(self):
        os.system('rm -rf '+filepath+filename3)
        print('old file log(write_log-filename3) is rm')
    def delete_old_log_file_4(self):
        os.system('rm -rf '+filepath+filename4)
        print('old file log(write_log-filename4) is rm')

    def write_log_txt(self, data):
        with open(filepath+filename,'a') as f:
            # time.sleep(0.02)
            f.write(str(data)+'\n')
            f.close()
    def write_log_txt_2(self, data):
        with open(filepath+filename2,'a') as f:
            # time.sleep(0.02)
            f.write(str(data)+'\n')
            f.close()
    def write_log_txt_3(self, data):
        with open(filepath+filename3,'a') as f:
            # time.sleep(0.02)
            f.write(str(data)+'\n')
            f.close()
    def write_log_txt_4(self, data):
        with open(filepath+filename4,'a') as f:
            # time.sleep(0.02)
            f.write(str(data)+'\n')
            f.close()            