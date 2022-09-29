#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
path ='/home/mnlab/Desktop/ryu/ryu/app/scada_log/'
filepath = path+'log/'
filename= '20220419_log.txt'
filename2= '20220419_simple_switch_13_log.txt'
class write_log():
    # def __init__(self):
        # self.delete_old_log_file()
    def delete_old_log_file(self):
        os.system('rm -rf '+filepath+filename)
        print('old file log is rm')
    def delete_old_log_file_2(self):
        os.system('rm -rf '+filepath+filename2)
        print('old file log is rm')

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