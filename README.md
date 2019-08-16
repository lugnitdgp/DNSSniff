# DNSSniff
A simple DNS Spy tool for LAN Networks


DNSSniff in action
![alt text](img/in_action.png)

## How to use ?
First,
*make sure IP forwarding is enabled in your system, otherwise target will lose internet connection*

#### How to check if IP forwarding is enabled or not ?
If you are using a Debian based linux distro (i.e Ubuntu) check output of
`cat /proc/sys/net/ipv4/ip_forward ` it should be `1`. If not, change it to `1`.

After this also check your firewall rules and *iptables* rules.
Usually ip forwarding is not blocked by firewalls.

Then it's simple, just  
`sudo python3 main.py -i <interface_name> -t <target_ip> -g <gateway_ip>`

For example `sudo python3 main.py -i wlo1 -t 192.168.0.101 -g 192.168.0.1`