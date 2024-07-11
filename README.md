# Turris Sentinel Dynamic Firewall client

This client receives Sentinel Dynamic Firewall (Sentinel:DynFW) updates over
ZMQ and updates ipset accordingly.


## Requirements

See `requirements.txt` for needed Python3 packages.


## Get started

Check whether your Linux distributions uses Nftables or legacy Ipset.
FirewallD supports both.

Then run the client (this example uses Nftables):
```sh
python client.py --backend nftables
```

Ipset is still the default backend and hence --backend can be omitted.

Check
```sh
python client.py --help
```
for available configuration options.
