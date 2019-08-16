# DNSSniff
A simple DNS Spy tool for LAN Networks


DNSSniff in action
![alt text](img/in_action.png)

## How to use ?
First,
*Make sure IP forwarding is enabled in your system, otherwise target will lose internet connection*

then it's simple, just  
`sudo python3 main.py -i <interface_name> -t <target_ip> -g <gateway_ip>`

for example `sudo python3 main.py -i wlo1 -t 192.168.0.101 -g 192.168.0.1`