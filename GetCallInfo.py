from mitmproxy import ctx
import mitmproxy.http
import mitmproxy.addonmanager
import calendar
import time
from datetime import datetime
import hashlib

#Use: mitmproxy -r [dump_path] -s GetCallInfo.py --set call=[call_url]
#dump_name is the mitmproxy dump file path
#call_url is the url to analize

class CallAnalizer:
    def __init__(self):
        self.num = 0
        self.call = None
        self.outputFileName = ""


    def writeToFile(self):
        timestamp = calendar.timegm(time.gmtime()).__str__()
        output_file = self.outputFileName + "_" + timestamp + ".txt"
        with open(output_file, 'w') as f:
            f.write(self.call.__str__())

    def load(self, loader):
        loader.add_option(
            name = "call_url",
            typespec = str,
            default = "",
            help = "Call to analize"
        )

    def request(self, flow: mitmproxy.http.HTTPFlow):
        url = flow.request.url
        if url == ctx.options.call_url:
            body = flow.request.text
            header = flow.request.headers
            method = flow.request.method
            self.outputFileName = flow.request.host
            time = datetime.fromtimestamp(flow.request.timestamp_start)
            if self.call == None:
                self.call = CallEntry(url, method, time, body, header)
            else:
                self.call.increment(time, body, header)

    def done(self):
        self.writeToFile()


class CallEntry:

    def __init__(self,call,method,time,body,header):
        super().__init__()
        self.call = call
        self.method = method
        self.number = 1
        self.bodies = []
        self.header = header
        self.headerChanges = []
        self.times = []
        self.times.append(time)
        self.bodies.append(body)
        self.headerChangesPerKey = {}

    def increment(self, time, body, header):
        self.number = self.number + 1
        self.times.append(time)
        bodyChangeFound = True
        for value in self.bodies:
            if value == body:
                bodyChangeFound = False
                break
        if bodyChangeFound:
            if len(self.bodies) > 0:
                self.bodies.append(f"body changed at {time}:\n{body}")
            else:
                self.bodies.append(f"{body}")
        for key, value in self.header.items():           
            if self.header[key] != header[key] and (key not in self.headerChangesPerKey or header[key] not in self.headerChangesPerKey[key]):
                self.headerChanges.append(f"{key} => {header[key]} at time {time}")
                if key not in self.headerChangesPerKey:
                    self.headerChangesPerKey[key] = []
                self.headerChangesPerKey[key].append(header[key]) 
    
    def __str__(self):
        self__repr__ = f"Call: {self.method} {self.call}\n\nNumber of Occurences: {self.number}\n\nHeaders\n"

        self__repr__ = self__repr__ + self.header__repr__() + "\n"

        self__repr__ = self__repr__ + "\n\nBodies\n"

        for body in self.bodies:
            self__repr__ = self__repr__ + body + "\n"

        return f"{self__repr__}\n\nOccurrences\n{self.frequency__repr__()}"

    def __repr__(self):
        return self.__str__()

    def frequency__repr__(self):
        times_repr = ""
        for time in self.times:
            times_repr = f"{times_repr}{self.call};{time}\n"
        return times_repr
    
    def header__repr__(self):
        header_repr = ""
        header_changes_repr = ""
        for key, value in self.header.items():
            header_repr = header_repr + f"{key} => {value}\n"
        for value in self.headerChanges:
            header_changes_repr = header_changes_repr + value + "\n"
        return header_repr + "Header Changes\n" + header_changes_repr

addons = [
    CallAnalizer()
]