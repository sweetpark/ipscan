from xml.etree.ElementTree import Element, SubElement, ElementTree, parse
import socket
import struct
import ipaddress
import time
import threading
import sys

PingResponse = {}
Running:bool
Result=[]
find_not_ip=["no ip scanned"]
scan_error=['Ipscan error']


def checksum(data) -> int:
    s = 0; n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+=int.from_bytes(data[i:i+2], byteorder='big')
 
    if n : s+=int.from_bytes(data[i:i+1], byteorder='big') # 잔여 바이트 처리
 
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
 
    s = ~s & 0xFFFF
    return s
 


def SendICMP(sock:socket.socket, ip:str):
    type = 8; code = 0; csum = 0; icmpid = 0; seq = 0
    TmpData = struct.pack("!BBHHH", type, code, csum, icmpid, seq)
    csum = checksum(TmpData)
    RealData = struct.pack("!BBHHH", type, code, csum, icmpid, seq)
    sock.sendto(RealData, (ip, 0))
 
 

def isPrefix(Mask:int) -> bool:
    if Mask<0 or Mask>32 : return False
    return True
 


def Prefix2Range(Mask:int) -> int:
    """
    넷마스크를 범위로 바꾼다.\n
    ex : 22 -> 1024
    ex : 24 -> 256
    """
    if isPrefix(Mask)==False : return 0
    inverse = 32 - Mask
    return 1<<inverse
 


def PrintUsage():
    """
    인자를 잘못 넣었을때 출력할 도움말
    """
    print("\nusage \n"
          "ex  only one ip     : python3 ipscan.py -o 8.8.8.8\n"
          "ex  subnet          : python3 ipscan.py -s 192.168.0.0 24\n"
          "ex  range           : python3 ipscan.py -r 192.168.0.0 192.168.0.20\n"
          "ex  assign range ip : python3 ipscan.py -a 192.168.0.100 192.168.3.100 192.168.0.0...\n")

 


def PingListenThread():
    sock = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.bind(("0.0.0.0", 0))
    while True:
        data, address = sock.recvfrom(1500)
        if address[0] in PingResponse :
            PingResponse[address[0]] = True



def xmlSend(result):
    filename='ipscanResult.xml'

    root=Element('root')
    ipscan=SubElement(root,'IPSCAN')
    for tmp in result:
        SubElement(ipscan,'RESULT').text = tmp
    
        
    tree=ElementTree(root)

    with open(filename, "wb") as file:
        tree.write(file, encoding='UTF-8', xml_declaration=True)

def findIpRange(startIP, endIP):
    try:
        reset=0
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #ICMP 로우소켓 만들기
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)

        if int(ipaddress.ip_address(startIP)) > int(ipaddress.ip_address(endIP)):
                xmlSend(scan_error)
                exit()
        start_ip = int(ipaddress.ip_address(startIP))
        end_ip = int(ipaddress.ip_address(endIP))
        
        ip_range=end_ip-start_ip+1

            
        for i in range(ip_range):
            ip = socket.inet_ntoa(int.to_bytes(start_ip, 4, "big")) # 네트워크 ID와 호스트ID를 합치면 IP가 됨
            PingResponse[ip] = False # 응답 받을 목록 초기화
            start_ip=start_ip+1
                    
        Listener = threading.Thread(target=PingListenThread, daemon=True) #핑 응답 받을 스레드 생성
        Listener.start()

        start_ip=int(ipaddress.ip_address(startIP)) #start_ip 초기화
        for i in range(ip_range):
            ip=socket.inet_ntoa(int.to_bytes(start_ip,4,"big"))
            if reset > 500:
                time.sleep(3)
                reset=0
            SendICMP(sock,ip)
            start_ip=start_ip+1
            reset=reset+1
        time.sleep(1) #응답 3초 대기

        sock.close()
    except :
        xmlSend(scan_error)
        quit()


def findIpSubnet(startIP,subnet):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #ICMP 로우소켓 만들기
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)

        address=startIP
        prefix=int(subnet)
        HostRange:int = Prefix2Range(prefix) # 이 대역 안에 총 몇개의 IP 가 있을 수 있는지?
        if not HostRange: xmlSend(PrintUsage()); exit()

        mask:int = 0xffffffff & ~((1 <<(32 - prefix)) - 1) # 네트워크ID 마스크
        RawIP = int(ipaddress.ip_address(address))
        NetworkID = mask & RawIP

        for HostID in range(HostRange):
            ip = socket.inet_ntoa(int.to_bytes(NetworkID+HostID, 4, "big")) # 네트워크 ID와 호스트ID를 합치면 IP가 됨
            PingResponse[ip] = False # 응답 받을 목록 초기화


        Listener = threading.Thread(target=PingListenThread, daemon=True) #핑 응답 받을 스레드 생성
        Listener.start()
            
        reset=0
        for HostID in range(HostRange):
            ip = socket.inet_ntoa(int.to_bytes(NetworkID+HostID, 4, "big")) # 네트워크 ID와 호스트ID를 합치면 IP가 됨
            if reset > 500:
                time.sleep(3)
                reset=0
            SendICMP(sock, ip) # Ping 전송
            reset=reset+1
        time.sleep(1) # 응답 3초 대기

        sock.close()
    except:
        xmlSend(scan_error)
        quit()


def findOneIP(startIP):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #ICMP 로우소켓 만들기
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
            
        address=startIP
        prefix:int=32
        HostRange:int = Prefix2Range(prefix) # 이 대역 안에 총 몇개의 IP 가 있을 수 있는지?
        if not HostRange: xmlSend(PrintUsage()); exit()        

        mask:int = 0xffffffff & ~((1 <<(32 - prefix)) - 1) # 네트워크ID 마스크
        RawIP = int(ipaddress.ip_address(address))
        NetworkID = mask & RawIP


        for HostID in range(HostRange):
            ip = socket.inet_ntoa(int.to_bytes(NetworkID+HostID, 4, "big")) # 네트워크 ID와 호스트ID를 합치면 IP가 됨
            PingResponse[ip] = False # 응답 받을 목록 초기화


        Listener = threading.Thread(target=PingListenThread, daemon=True) #핑 응답 받을 스레드 생성
        Listener.start()
            

        for HostID in range(HostRange):
            ip = socket.inet_ntoa(int.to_bytes(NetworkID+HostID, 4, "big")) # 네트워크 ID와 호스트ID를 합치면 IP가 됨
            SendICMP(sock, ip) # Ping 전송
            
        time.sleep(1) # 응답 3초 대기

        sock.close()
    except:
        xmlSend(scan_error)
        quit()

def findAssignIP(ip_list):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) #ICMP 로우소켓 만들기
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        str2int_ip=[]

        for ip in ip_list:
            str2int_ip.append(int(ipaddress.ip_address(ip)))

        for ip in str2int_ip:
            ip = socket.inet_ntoa(int.to_bytes(ip, 4, "big")) # 네트워크 ID와 호스트ID를 합치면 IP가 됨
            PingResponse[ip] = False # 응답 받을 목록 초기화

                    
        Listener = threading.Thread(target=PingListenThread, daemon=True) #핑 응답 받을 스레드 생성
        Listener.start()

        for ip in str2int_ip:
            ip=socket.inet_ntoa(int.to_bytes(ip,4,"big"))
            SendICMP(sock,ip)
        
        time.sleep(1)

        sock.close()
    except :
        xmlSend(scan_error)
        quit()


def main():

    try:
        if sys.argv[1]=="-r":
            findIpRange(sys.argv[2],sys.argv[3])
        elif sys.argv[1]=="-s":
            findIpSubnet(sys.argv[2],sys.argv[3])
        elif sys.argv[1]=="-o":
            findOneIP(sys.argv[2])
        elif sys.argv[1]=="-a":
            ip_list=[]
            for i in range(2,len(sys.argv)):
                ip_list.append(sys.argv[i])
            findAssignIP(ip_list)
        else:
            quit()
    except:
        xmlSend(scan_error)
        PrintUsage()
        exit()

    for tmp in PingResponse :
        tmp:dict
        if PingResponse[tmp]==True: 
            Result.append(tmp)
    
    if len(Result)==0:
        xmlSend(find_not_ip)
    else:
        xmlSend(Result)


main()
quit()        
