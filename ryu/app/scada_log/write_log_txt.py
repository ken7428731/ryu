#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
path ='/home/mnlab/Desktop/ryu/ryu/app/scada_log/'
filepath = path+'log/'
date_string='20220917_ryu_no_attack'
filename= date_string+'_log.txt'
class write_log():
    # def __init__(self):
        # self.delete_old_log_file()
    def delete_old_log_file(self):
        os.system('rm -rf '+filepath+filename)
        print('old file log(write_log-filename) is rm')

    def write_log_txt(self, data):
        with open(filepath+filename,'a') as f:
            # time.sleep(0.02)
            f.write(str(data)+'\n')
            f.close()     