import nmap3

def port_scan(ip):
    nmap = nmap3.Nmap()
    results = nmap.nmap_os_detection(ip)
    print(results)
    return results
port_scan('127.0.0.1')