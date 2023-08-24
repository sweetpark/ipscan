IP scan 값 범위 (ip 1개, subnet을 이용한 ipscan, 범위를 이용한 ipscan, 특정 ipscan)


only one ip       : python3 ipscan.py -o 8.8.8.8\n

subnet              : python3 ipscan.py -s 192.168.0.0 24\n

range                : python3 ipscan.py -r 192.168.0.0 192.168.0.20\n

assign range ip : python3 ipscan.py -a 192.168.0.100 192.168.3.100 192.168.0.0...\n


<br>Result</br>
-> $PWD/ipscanResult.xml
