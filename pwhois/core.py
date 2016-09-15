#pwhois.py
#a Python pwhois library
#by Kevin Tyers
#Testing/working for 2.7.2, but I assume it should work with all 2.7.x releases
"""
I've tested the bulk query feature up to 25,000 queries, but it should work above that number.
"""
import socket
import time
import re

pw_server = 'whois.pwhois.org'
pw_port = 43

class ip(object):
    """This is the data returned by a pwhois lookup, format is modeled after the output of whob"""

    def __init__(self, ip="", origin_as="", prefix="", as_path="", as_org_name="", org_name="", net_name="",
                 cache_date="", latitude="", longitude="", city="", region="", country="", cc=""):
        self.ip = ip
        self.origin_as = origin_as
        self.prefix = prefix
        self.as_path = as_path
        self.as_org_name = as_org_name
        self.org_name = org_name
        self.net_name = net_name
        self.cache_date = cache_date
        self.latitude = latitude
        self.longitude = longitude
        self.city = city
        self.region = region
        self.country = country
        self.cc = cc

    def __str__(self):
        """Replicates whob output"""
        return """IP: {}
Origin-AS: {}
Prefix: {}
AS-Path: {}
AS-Org-Name: {}
Org-Name: {}
Net-Name: {}
Cache-Date: {}
Latitude: {}
Longitude: {}
City: {}
Region: {}
Country: {}
Country-Code: {}""".format(self.ip, self.origin_as, self.prefix, self.as_path, self.as_org_name, self.org_name,
                           self.net_name, self.cache_date, self.latitude, self.longitude, self.city, self.region,
                           self.country, self.cc)

    @classmethod
    def lookup(cls, query):
        """Single query, takes a single IP (represented as a string) and returns a pwhois_obj."""
        if ip_check(query):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((pw_server, pw_port))
            query_bytes = (query + "\r\n").encode()
            s.send(query_bytes)
            resp = s.recv(500)
            whois_data = resp.split('\n')
            try:
                return ip(whois_data[0].split(': ')[1], whois_data[1].split(': ')[1],
                              whois_data[2].split(': ')[1],
                              whois_data[3].split(': ')[1], whois_data[4].split(': ')[1],
                              whois_data[5].split(': ')[1],
                              whois_data[6].split(': ')[1], whois_data[7].split(': ')[1],
                              whois_data[8].split(': ')[1],
                              whois_data[9].split(': ')[1], whois_data[10].split(': ')[1],
                              whois_data[11].split(': ')[1],
                              whois_data[12].split(': ')[1], whois_data[13].split(': ')[1])
            except:
                return "Could not retrieve information about {}".format(query)
        else:
            return "Input {} is invalid".format(query)

    @classmethod
    def bulk_lookup(cls, query, verbosity=False):
        """Bulk lookup, takes a list of IPs and returns a dictionary of results. Use 'v' to turn on verbose mode
        and get back a list of invalid IPs in a query."""
        q_set = set()
        bad_set = set()
        pw_server = 'whois.pwhois.org'
        pw_port = 43
        p_obj_dict = {}
        response = ""
        for ip in query:
            if ip_check(ip):
                q_set.add(ip)
            else:
                bad_set.add(ip)
        q_list = list(q_set)
        batches = [q_list[x:x + 200] for x in xrange(0, len(q_list), 200)]
        for batch in batches:
            q_str = ""
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((pw_server, pw_port))
            for ip in batch:
                if ip.endswith('\n'):  #If you opened a file, this will remove the new line characters.
                    q_str += "{}\r\n".format(ip[:-1])
                else:
                    q_str += "{}\r\n".format(ip)
            queryBytes = ('begin\r\napp="Python pwhois BULK_FILE"\r\n{}end\r\n'.format(q_str)).encode()
            s.send(queryBytes)
            time.sleep(1.5)
            response += s.recv(65535)
        for entry in response[1:].split('\n\n'):
            whois_data = entry.split('\n')
            if whois_data[1].split(': ')[1] == 'NULL':
                #Null results don't return a country code, so they need to be handled separately
                p_obj = ip(whois_data[0].split(': ')[1], whois_data[1].split(': ')[1],
                                  whois_data[2].split(': ')[1],
                                  whois_data[3].split(': ')[1], whois_data[4].split(': ')[1],
                                  whois_data[5].split(': ')[1],
                                  whois_data[6].split(': ')[1], whois_data[7].split(': ')[1],
                                  whois_data[8].split(': ')[1],
                                  whois_data[9].split(': ')[1], whois_data[10].split(': ')[1],
                                  whois_data[11].split(': ')[1],
                                  whois_data[12].split(': ')[1], whois_data[13].split(': ')[1])
                p_obj_dict[whois_data[0].split(': ')[1]] = p_obj
            else:
                try:
                    p_obj = ip(whois_data[0].split(': ')[1], whois_data[1].split(': ')[1],
                                      whois_data[2].split(': ')[1],
                                      whois_data[3].split(': ')[1], whois_data[4].split(': ')[1],
                                      whois_data[5].split(': ')[1],
                                      whois_data[6].split(': ')[1], whois_data[7].split(': ')[1],
                                      whois_data[8].split(': ')[1],
                                      whois_data[9].split(': ')[1], whois_data[10].split(': ')[1],
                                      whois_data[11].split(': ')[1],
                                      whois_data[12].split(': ')[1], whois_data[13].split(': ')[1])
                    p_obj_dict[whois_data[0].split(': ')[1]] = p_obj
                except:
                    pass
        if verbosity == True:
            return p_obj_dict, list(bad_set)
        else:
            return p_obj_dict


class asn(object):
    def __init__(self, asn, ranges):
        self.asn = asn
        self.ranges = list(ranges)

    @classmethod
    def lookup(cls, as_n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((pw_server, pw_port))
        query_bytes = 'app="Python pwhois client" routeview source-as={}\r\n'.format(as_n).encode()
        s.send(query_bytes)
        resp = recvall(s)
        range_output = resp.split("\n")[2:-1]
        ranges = set()
        for range in range_output:
            ranges.add(range.lstrip("*> ").split(" ")[0])
        return asn(as_n, ranges)

    def __str__(self):
        return "ASN {}\nRanges:\n{}".format(self.asn, "\n".join([r for r in self.ranges]))


def ip_check(ip):
    ip_reg = re.compile(
        '(?:^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[0-9]{1,2})$)')
    if ip_reg.match(ip):
        return True
    else:
        return False


def recvall(sock):
    data = ""
    part = None
    while part != "":
        part = sock.recv(4096)
        data += part
    return data
