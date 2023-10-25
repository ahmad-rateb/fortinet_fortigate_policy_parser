# Fortinet FortiGate - Firewall Policy Parser

Finds IP networks that communicate with a System Interface/Zone

## Input Arguments

- `--username` for Username
- `--device` for FortiGate Hostname/IP
- `--vdom` for VDOM name
- `--intf` for Interface name
- `--log` Enable informational-type logging (optional)

> The script will look for the zone name (if any) that references the provided interface

## User Input

- Password

## Terminology

- Self-side: The side at which our Target Interface/Zone resides
- Other-side: Opposite side to our Target Interface/Zone

## Script Output

- A CSV file which includes one of the following statuses for each captured subnet
  - `OK`: Subnet is routed via one of the Other-side's zones
  - `Loose`: Subnet is not routed via any of the Other-side's zones, but is parent (i.e. a supernet) to one or more routable children via these zones

## Script Operation

- Finds zone name of each interface, otherwise, interface itself is a zone
- Maps each FW Named Address and/or Address-Group to its set of IP addresses
  - If FW Named Address is a range, it is expanded into /32 or /128 hosts
- Downloads the VDOM's IPv4 & IPv6 routing tables and store them in a tree
  (CIDR-Trie data structure)
- Parses all policies for communications with the Target Interface
  - Consider only "enabled" policies with "accept" action
  - Ignore Any-to-Any policies (too generic)
  - If Self-side has our Target Interface/Zone or is Zone "any":
    - Run uRPF check for each subnet in that side until one routable
      subnet via Target Interface is found, else, the policy is ignored
    - Run uRPF check for each subnet in the Other-side and only capture
      subnet(s) which pass the uRPF check, else, the policy is ignored
  - If Other-side is Zone "any":
    - Capture subnets which, or any of their children, have routes
  - If Other-side has the Target Interface, ignore subnets routed via it
  - If a subnet points to Null and has no routable children, it's ignored
  - Self-uRPF check must pass before any processing to the Other-side
  - If Self or Other sides failed in uRPF checks, info message is logged

## Preset Values

- Timeout for HTTP login/logout requests set to 10 seconds
- Timeout for REST API calls is set to 60 seconds

## Required Python Modules

- requests
- pytricia

## Python Modules Installation

```bash
$ pip3 install -r requirements.txt
```

## How to use

Run the script and provide the arguments followed by the Password as mentioned in the 'Input Arguments' and 'User Input' sections above

```bash
$ python3 fortinet_fortigate_policy_parser.py --username your_username --device hostname_or_ip --vdom vdom_name --intf interface_name [--log]
Password:
```

> Script was developed in Python 3.10. Minimum required version is Python 3.7.
