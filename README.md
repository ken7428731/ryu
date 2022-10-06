基於軟體定義網路技術之工業控制場域防護系統-Ryu Controller
=====

環境設定資訊(Environmental Setting Information):
===========
- Python3 Version: 3.8.1  
- OS version: Ubuntu 20.04.4  

網路拓樸(Network Topology):
===========
<p align="center" width="100%">
    <img src="/ryu/Everyday_set_log/20220921/Beverage_and_food_processing_factory-network_topology.jpg"> 
</p>
此程式部署在如上圖 紅色框框上。  

其他設備環境設定(Other Devices Setting):
===========
可以參考此 [設定頁面](https://hackmd.io/@rrpSFv-qSLunmXT6FGkwBg/SksRTxVzo)  

安裝步驟(Installation Steps):
===========
安裝 git、pip3  
   `sudo apt install git python3-pip`

下載 SDN_SCADA  
   `git clone https://github.com/ken7428731/ryu.git`

進到ryu檔案  
   `cd ryu/`

安裝環境  
   `sudo pip3 install .`

執行步驟(Execution Steps):
===========
執行程式  
   `ryu-manager ryu/app/simple_switch_15_Scada_System.py`

各程式用途(Program Functions):
===========
Device_Information.json 為飲料食品加工廠的設備資訊。  
Load_SCADA_Information_Data.py 載入飲料食品加工廠的設備資訊。  
simple_switch_15_Scada_System.py 為檢測與防禦系統的程式。  
modbus_tcp.py 為解析Modbus TCP封包。  
write_log_txt.py 為寫紀錄檔(log)功能。    

有問題時(Question)
=============
如果您在安裝時收到一些錯誤消息，請確認構建所需 Python 套件的依賴關係。  

On Ubuntu(16.04 LTS or later)  
  `sudo apt install gcc python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev`  

參考(Reference)
=======
- ryu官網: https://ryu-sdn.org/
- ryu github: https://github.com/faucetsdn/ryu
- https://stackoverflow.com/questions/49971882/delete-flows-matching-specific-cookie-openflow-1-3-5-spec-support-by-openvswit
- https://gist.github.com/aweimeow/d3662485aa224d298e671853aadb2d0f
- https://umodbus.readthedocs.io/en/latest/functions.html
- https://stackoverflow.com/questions/53065365/how-can-i-send-with-struct-pack-type-over-modbus-tcp
- Industrial Control Field Protection System Based on Software-defined Network Technology: https://hdl.handle.net/11296/3zh3g6
- https://zh.wikipedia.org/zh-tw/VMware_Workstation
- https://www.openvswitch.org/