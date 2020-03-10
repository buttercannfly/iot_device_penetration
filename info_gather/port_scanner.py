import nmap

def port_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip,'22-443')
    for host in nm.all_hosts():
        print('Host: %s(%s)'%(host,nm[host].hostname()))
        print('State:%s'%nm[host].state())
        for proto in nm[host].all_protocols():
            print("Protocol:%s"%proto)
            lport = nm[host][proto].keys()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))


port_scan('127.0.0.1')