from datetime import datetime, date, time, timedelta
import ipaddress

class DNSEvent:

    def __init__(
        self,
        timestamp,
        src_ip,
        dst_ip,
        query,
        qtype,
        packet_length,
        response_length,
        rcode
    ):
        self.timestamp = self.getTimeStamp(timestamp)
        self.src_ip = self.getSourceIP(src_ip)
        self.dst_ip = self.getDestIP(dst_ip)

        self.query = self.getQuery(query)
        self.domain = self.getDomain(self.query)
        self.subdomain = self.getSubDomain(self.query)

        self.qtype = self.getNormalized(qtype)
        self.query_length = self.getQueryLength(self.query)

        self.packet_length = self.getPacketLength(packet_length)
        self.response_length = self.getResponseLength(response_length)

        self.rcode = self.getNormalizedRcode(rcode)
        self.is_nxdomain = self.is_nxdomain(rcode)


    def getTimeStamp(self,time_str):
        year = int(time_str[:4])
        month = int(time_str[5:7])
        day = int(time_str[8:10])
        hour = int(time_str[11:13])
        minute = int(time_str[14:16])
        sec = int(time_str[17:19])
        microsec = int(time_str[20:23])*1000

        return datetime(year,month,day,hour,minute,sec,microsec)

    def getSourceIP(self,source_ip):
        return ipaddress.IPv4Address(source_ip)

    def getDestIP(self,dest_ip):
        return ipaddress.IPv4Address(dest_ip)

    def getQuery(self,query_str):
        lst = list(query_str)

        # removing the trailing . from prefix
        for i in range(0,len(lst)):
            if lst[i] == '.':
                lst[i] = '*'
            else:
                break

        # removing the trailing . from suffix
        for i in range(len(lst)-1,-1,-1):
            if lst[i] == '.':
                lst[i] = '*'
            else:
                break

        ans_str = ''
        for x in lst:
            if x != '*': ans_str += x
        return ans_str

    def getDomain(self,query_str):
        # this takes a fully qualified DNS query

        lst = query_str.split(".")
        n = len(lst)
        return lst[n-2]+"."+lst[n-1]

    def getSubDomain(self,query_str):
        # this takes a fully qualified DNS query

        lst = query_str.split(".")
        if len(lst) <= 2:
            return ""
        return ".".join(lst[:-2])

    def getNormalized(self,q_type):
        return q_type.upper()

    def getQueryLength(self,query_str):
        # this takes a fully qualified DNS query
        return len(query_str)

    def getPacketLength(self,n):
        return n

    def getResponseLength(self,n):
        if type(n).__name__  == "str" : return int(n)
        return n

    def getNormalizedRcode(self,response_str):
        if response_str is None: return None
        if type(response_str).__name__  == "int" : return str(response_str)
        return response_str.upper()

    def is_nxdomain(self,response_str):
        # nxdomain = non_existent_domain -> when a domain name lookup fails at DNS server
        rcose_str = self.getNormalizedRcode(response_str)

        return rcose_str == "NXDOMAIN" or rcose_str == "3"
         


    

