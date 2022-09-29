import datetime

class epoch_to_datetime:
    def get_datetime(self,msg):
        timedate=datetime.datetime.fromtimestamp(msg)
        return str(timedate)