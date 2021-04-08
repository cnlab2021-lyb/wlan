## Initialization ##

``` sh
# Create AP
create_ap --daemon -n wlp3s0 'MyAccessPoint' ''
# Enable IPv4 forwarding
sysctl net.ipv4.ip_forward=1
# Masquerade from an interface w/ Internet
iptables -t nat -A POSTROUTING -o enp2s0 -j MASQUERADE
# Redirect to portal by default
iptables -t nat -A PREROUTING -i ap0 -p tcp -j REDIRECT --to-ports 8000
# Set wireless interface in environment
export IFNAME=ap0
```
