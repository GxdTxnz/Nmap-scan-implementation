from scapy.all import *


def icmp_ping(target_host):
    conf.verb = 0
    icmp_request = IP(dst=target_host)/ICMP()
    response = sr1(icmp_request, timeout=1, verbose=0)
    
    result = None
    
    if response is not None:
        if response.haslayer(ICMP) and response[ICMP].type == 0:
            result = f"Хост {target_host} в сети" 
        else:
            resul = f"_"
    else:
        resul = f"_"
        
    return result
        
        
    
    
'''    
    try:
        response = sr1(icmp_request, timeout=1, verbose=0)
        if response and response.haslayer(ICMP) and response[ICMP].type == 0:
            return host, "Up"
    except:
        pass
    return host, "Down"
'''