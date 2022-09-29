#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
path ='/home/mnlab/Desktop/ryu/ryu/app/SCADA_Device_Information/'
filename=path+'Device_Information.json'
class Load_Data():
    def Load_Information(self):
        with open(filename,newline='') as jsonfile:
            data=json.load(jsonfile)
            # 或者這樣
            # data = json.loads(jsonfile.read())
            # print(data)
            return data


# Load_Object=Load_Data()
# Load_Object.Load_Information()
