"""
Finds IP networks that communicate with a System Interface/Zone

Terminology when evaluating a Firewall Policy:
    - Self-side: The side at which our Target Interface/Zone resides
    - Other-side: Opposite side to our Target Interface/Zone

Script Operation:
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

Input Arguments:
    - `--username` for Username
    - `--device` for FortiGate Hostname/IP
    - `--vdom` for VDOM name
    - `--intf` for Interface name
    - `--log` Enable informational-type logging (optional)

User Input:
    - Password

Script Output:
    - CSV file with the status of each captured subnet
        1) `OK`: Subnet is routed via one of the Other-side's zones
        2) `Loose`: Subnet is not routed via any of the Other-side's zones, but
                    is parent to one or more routable children via these zones

Preset Values:
    - Timeout for HTTP login/logout requests set to 10 seconds
    - Timeout for REST API calls is set to 60 seconds
"""

from typing import List, Dict, Set, Tuple, DefaultDict, Optional, Iterator
from ipaddress import ip_network, ip_address, summarize_address_range
from collections import defaultdict
from argparse import ArgumentParser
from getpass import getpass
import logging
import csv

from pytricia import PyTricia
import requests
import urllib3


class BadAPICall(ValueError):
    """To be raised for bad FortiGate HTTP/REST API calls"""


class WrongLoginCredentials(ValueError):
    """To be raised after invalid login attempt"""


class InterfaceNotFoundInVDOM(ValueError):
    """To be raised when an interface doesn't belong to a given VDOM"""

    def __init__(self, intf: str, curr_vdom: str, target_vdom: str) -> None:
        msg = f"'{intf}' belongs to VDOM '{curr_vdom}' not '{target_vdom}'"
        super().__init__(msg)


class FortiConnect:
    """
    A REST API connection-handler for FortiGate that manages HTTPS session
    establishment and termination.

    Provides a method to access a given collection by providing its path,
    name and optionally filters by the master key as well as the VDOM.
    User should also provide the API in-check (e.g. cmdb, monitor, etc.).
    """

    def __init__(self, username: str, password: str, device: str) -> None:
        """Constructor"""

        self.device = device
        self.username = username
        self.password = password
        self.cookiejar = None

    def __enter__(self):
        """Connect to FortiGate"""

        self.login()
        return self

    def __exit__(self, *args) -> None:
        """Graceful logout from FortiGate"""

        self.logout()

    def _set_cookies(self, cookies) -> None:
        """Set cookies as an instance variable of the object"""

        if cookies:
            self.cookiejar = cookies
        else:
            raise WrongLoginCredentials("Wrong username or password provided")

    def login(self) -> None:
        """POST login request and save Cookies"""

        login_url = f"https://{self.device}/logincheck"
        login_creds = {'username': self.username, 'secretkey': self.password}
        login_resp = requests.post(login_url, data=login_creds, verify=False, timeout=10)
        self._set_cookies(login_resp.cookies)

    def logout(self) -> None:
        """POST logout request"""

        logout_url = f"https://{self.device}/logout"
        requests.post(logout_url, cookies=self.cookiejar, verify=False, timeout=10)

    def _make_url(
            self,
            api: str,
            path: str,
            name: str,
            mkey: Optional[str],
            vdom: Optional[str]) -> str:
        """Format the URL based on the Collection's Path, Name & MKey"""

        url = f"https://{self.device}/api/v2/{api}/{path}/{name}/"
        if mkey:
            url += f"{mkey}/"
        if vdom:
            url += f"?vdom={vdom}"
        return url

    def _validate_status_code(
            self,
            status_code: int,
            api: str,
            path: str,
            name: str,
            mkey: Optional[str],
            vdom: Optional[str]) -> None:
        """Validate returned status code of the HTTP request"""

        if status_code != 200:
            if status_code in (403, 424):
                msg = f"VDOM '{vdom}' doesn't exist"
            elif status_code == 404:
                msg = f"Bad Master Key '{mkey}' in '{path}/{name}' or unkown API call for '{api}'"
            else:
                msg = f"Bad Collection Path '{path}' and/or Name '{name}' for '{api}' API"
            raise BadAPICall(msg)

    def get_collection(
            self,
            api: str,
            path: str,
            name: str,
            *,
            mkey: Optional[str] = None,
            vdom: Optional[str] = None) -> List[Dict]:
        """Performs GET request to a given URL and returns List of Dict objects"""

        url = self._make_url(api, path, name, mkey, vdom)
        get_request = requests.get(url, cookies=self.cookiejar, verify=False, timeout=60)
        self._validate_status_code(get_request.status_code, api, path, name, mkey, vdom)
        get_reply = get_request.json()
        objs: List[Dict] = get_reply["results"]
        return objs


class ModPyTricia(PyTricia):
    """
    Modified PyTricia class (CIDR-Trie data structure) with additional methods
    """

    def __init__(self, ip_bits: int) -> None:
        """Explicit super constructor call for clarity"""

        super().__init__(ip_bits)

    def _children_interfaces_generator(self, ip_net: str) -> Iterator[str]:
        """Yields exit-interfaces of children of a given IP network"""

        children: List[str] = self.children(ip_net)
        for child in children:
            exit_intf: Optional[str] = self.get(child)
            if exit_intf is not None:
                yield exit_intf

    def get_children_interfaces(self, ip_net: str) -> Set[str]:
        """Return exit-interfaces of each child of a given network"""

        children_interfaces = set()
        if self.has_key(ip_net):
            children_interfaces.update(self._children_interfaces_generator(ip_net))
        else:
            self.insert(ip_net, "TEMP")
            children_interfaces.update(self._children_interfaces_generator(ip_net))
            self.delete(ip_net)
        return children_interfaces

    def urpf(self, ip_net: str, intf: str) -> bool:
        """
        Test if the given interface is actually the exit-interface of the given
        network, or, if the network has children and the interface is used to
        route any child.
        """

        return (intf == self.get(ip_net)) or (intf in self.get_children_interfaces(ip_net))


class PolicyParser:
    """
    A parser that provides methods to test policies which reference a given
    interface (a.k.a target_intf) for bi-directional routing.
    """

    def __init__(
            self,
            target_intf: str,
            zones_to_intfs: DefaultDict[str, Set[str]],
            fw_addr_to_ips: DefaultDict[str, Set[str]],
            routing_table: ModPyTricia,
            ver: str) -> None:
        """Constructor"""

        self.target_intf = target_intf
        self.zones_to_intfs = zones_to_intfs
        self.fw_addr_to_ips = fw_addr_to_ips
        self.routing_table = routing_table
        self.ver = ver

    @property
    def srcaddr_key(self) -> str:
        """Returns the key name to access a policy's src named-address(es)"""

        return "srcaddr" if self.ver == "IPv4" else "srcaddr6"

    @property
    def dstaddr_key(self) -> str:
        """Returns the key name to access a policy's dst named-address(es)"""

        return "dstaddr" if self.ver == "IPv4" else "dstaddr6"

    def is_enabled(self, policy: Dict) -> bool:
        """Policy is active if it is enabled and policy action is accept"""

        return (policy["action"] == "accept") and (policy["status"] == "enable")

    def is_any_to_any(self, policy: Dict) -> bool:
        """Checks if policy is any-to-any via first zone name in each direction"""

        return policy["srcintf"][0]["name"] == policy["dstintf"][0]["name"] == "any"

    def extract_interfaces_from_policy_zones(
            self,
            policy: Dict) -> Tuple[Set[str], Set[str]]:
        """
        At each policy direction, extract the interfaces associated with each
        zone and add them in a set (i.e. replace zones by their interfaces),
        then return the interfaces sets for both drections.
        """

        src_intfs, dst_intfs = set(), set()
        for intf_dir, intfs_set in zip(("srcintf", "dstintf"), (src_intfs, dst_intfs)):
            for zone_obj in policy[intf_dir]:
                zone_name: str = zone_obj["name"]
                intfs: Set[str] = self.zones_to_intfs.get(zone_name, {"any"})
                intfs_set.update(intfs)
        return src_intfs, dst_intfs

    def _self_urpf(self, pid: int, self_addrs: List[Dict], side: str) -> bool:
        """
        At self-side, where our Target Intf/Zone exists, test each IP Net in our
        side for routing through Target Intf (to eliminate non-usable policies).

        At least one IP Net should pass the check for self-side to be valid.

        Failure in validation could mean:
            - No single IP Net is routable via Target Intf [bad policy] or,
            - Target Intf is part of a multi-intf zone [policy isn't meant for it]
        """

        for obj in self_addrs:
            named_addr: str = obj["name"]
            for ip_net in self.fw_addr_to_ips[named_addr]:
                # Return once an IP Net is found routable via Target Intf
                if self.routing_table.urpf(ip_net, self.target_intf):
                    return True
        logging.info(f"Self-routing check failed in Policy ID #{pid} @{side} side")
        return False

    def _other_urpf_results(
            self,
            pid: int,
            other_addrs: List[Dict],
            other_intfs: Set[str],
            side: str) -> Iterator[Tuple]:
        """
        At other-side (facing our Target Intf/Zone), extract IP Nets from
        their FW Named Address/Address-Groups and test each IP Net for routing
        via any of other-side's zones (to eliminate non-usable policies).

        Only IP Nets passing the test are captured, failed ones are silently
        ignored. If no single IP Net passed the test, a log is generated.

        Failure in validation means no single IP Net is routable via any
        of other-side's zones [bad policy] and this can also happen if routing
        is done via a Null interface (because it is not a member of any zone)

        Upon successful uRPF check for the other-side, it yields tuple(s):
            (Policy ID, IP Version, Named Address, IP Network, Route, Status)
        """

        other_routing = False
        for obj in other_addrs:
            named_addr: str = obj["name"]
            for net in self.fw_addr_to_ips[named_addr]:
                # Find the actual Route and the Exit-Interface of the IP Net
                route: Optional[str] = self.routing_table.get_key(net)
                exit_intf: Optional[str] = self.routing_table.get(net)
                # Ensure that IP Nets in-check are not routable via our own interface
                if exit_intf != self.target_intf:
                    # One of the other-side's zones should reference the exit-interface,
                    # or, if the other-side is zone "any" then the exit-interface
                    # should point to a route (hence non-None) via a non-Null interface
                    if (exit_intf in other_intfs) or (("any" in other_intfs) and (exit_intf not in (None, "Null"))):
                        other_routing = True
                        yield (pid, self.ver, named_addr, net, route, "OK")
                    else:
                        # If there's no route via any of the other side's zones'
                        # referenced interfaces, then try to see if the network
                        # itself has children, where, at least, one child is
                        # routable via the zones. It can also happen that the
                        # other side is zone "any", thus we still need to check
                        # if such network (or any of its children) has a route
                        children_interfaces = self.routing_table.get_children_interfaces(net)
                        if children_interfaces.intersection(other_intfs) or (("any" in other_intfs) and children_interfaces):
                            other_routing = True
                            yield (pid, self.ver, named_addr, net, "N/A", "Loose")
        if not other_routing:
            logging.info(f"Other-routing check failed in Policy ID #{pid} @{side} side")

    def parse(self, policy: Dict) -> Iterator[Iterator[Tuple]]:
        """
        Parses a Firewall Policy to find the actual route of each IP Network
        that communicates with our Target-Interface/Zone.

        Policy must be enabled and not an any-to-any policy.

        Yields another generator; The results yielded by the uRPF check at the
        other-side facing our Target-Interface/Zone.
        """

        if self.is_enabled(policy) and not self.is_any_to_any(policy):

            pid: int = policy['policyid']
            src_addrs: List[Dict] = policy[self.srcaddr_key]
            dst_addrs: List[Dict] = policy[self.dstaddr_key]
            src_intfs, dst_intfs = self.extract_interfaces_from_policy_zones(policy)

            if src_intfs.intersection({self.target_intf, "any"}) and self._self_urpf(pid, src_addrs, "src"):
                yield self._other_urpf_results(pid, dst_addrs, dst_intfs, "dst")

            if dst_intfs.intersection({self.target_intf, "any"}) and self._self_urpf(pid, dst_addrs, "dst"):
                yield self._other_urpf_results(pid, src_addrs, src_intfs, "src")


def query_intf_in_vdom(target_intf: str, vdom: str, forti_rest: FortiConnect) -> None:
    """Check whether target interface is in the given VDOM"""

    logging.info(f"Checking whether interface {target_intf} is in VDOM {vdom}")
    objs = forti_rest.get_collection("cmdb", "system", "interface", mkey=target_intf, vdom=vdom)
    curr_intf_vdom: str = objs[0]["vdom"]
    if curr_intf_vdom != vdom:
        raise InterfaceNotFoundInVDOM(target_intf, curr_intf_vdom, vdom)


def map_zones_to_interfaces(
        vdom: str,
        forti_rest: FortiConnect) -> DefaultDict[str, Set[str]]:
    """Return Zone-to-Interface(s) dictionary"""

    sys_zones_objs = forti_rest.get_collection("cmdb", "system", "zone", vdom=vdom)
    logging.info(f"Mapping Zones to Interfaces as in VDOM {vdom}")
    zones_to_intfs = defaultdict(set)
    intfs_in_zones = set()
    for zone_obj in sys_zones_objs:
        zone_name: str = zone_obj["name"]
        for intf_obj in zone_obj["interface"]:
            intf_name: str = intf_obj["interface-name"]
            zones_to_intfs[zone_name].add(intf_name)
            intfs_in_zones.add(intf_name)

    # Consider zoneless interfaces as zones which point to themselves
    sys_intfs_objs = forti_rest.get_collection("cmdb", "system", "interface", vdom=vdom)
    logging.info("Finding Zoneless Interfaces")
    for intf_obj in sys_intfs_objs:
        intf_name = intf_obj["name"]
        intf_vdom = intf_obj["vdom"]
        if (intf_vdom == vdom) and (intf_name not in intfs_in_zones):
            zones_to_intfs[intf_name] = {intf_name}

    return zones_to_intfs


def fw_addr_to_ips_generator(objs: List[Dict]) -> Iterator[Tuple[str, str]]:
    """
    Iterate through objects of a Firewall Address collection then yield each
    Named-Address and its associated IP address(es).
    """

    for obj in objs:
        named_addr: str = obj["name"]
        addr_type: str = obj["type"]
        if addr_type == "ipmask":
            net_with_mask: str = obj["subnet"].replace(" ", "/")
            net_with_pfxlen = ip_network(net_with_mask).with_prefixlen
            yield named_addr, net_with_pfxlen
        elif addr_type == "ipprefix":
            net_with_pfxlen: str = obj["ip6"]
            yield named_addr, net_with_pfxlen
        elif addr_type == "iprange":
            start_ip, end_ip = ip_address(obj["start-ip"]), ip_address(obj["end-ip"])
            summarized_range = summarize_address_range(start_ip, end_ip)
            for net in summarized_range:
                for host in net:
                    # Expand the range into /32 or /128 host addresses
                    net_with_pfxlen = ip_network(host).with_prefixlen
                    yield named_addr, net_with_pfxlen


def fw_addrgrp_to_member_generator(objs: List[Dict]) -> Iterator[Tuple[str, str]]:
    """
    Iterate through objects of a Firewall Address-Group collection then yield
    each Named-Address-Group and its associated Named-Address(es) (aka member(s)).
    """

    for obj in objs:
        addrgrp: str = obj["name"]
        addrgrp_members: List[Dict] = obj["member"]
        for member_obj in addrgrp_members:
            member: str = member_obj["name"]
            yield addrgrp, member


def map_fw_addr_to_ips(vdom: str, forti_rest: FortiConnect) -> List[DefaultDict[str, Set[str]]]:
    """
    Map each IPv4 and IPv6 FW Address/Address-Group to their set of IP(s) and
    return their dictionaries.
    """

    ret = []
    for fw_addr, fw_addrgrp in zip(("address", "address6"), ("addrgrp", "addrgrp6")):
        # A FW Address usually points to one IP, but in case of Ranges or
        # Address-Groups, then it would point to a range or group (set) of IPs
        fw_addr_to_ips = defaultdict(set)

        fw_addr_objs = forti_rest.get_collection("cmdb", "firewall", fw_addr, vdom=vdom)
        logging.info(f"Mapping each Firewall {fw_addr} to its IP(s)")
        for named_addr, net_with_pfxlen in fw_addr_to_ips_generator(fw_addr_objs):
            fw_addr_to_ips[named_addr].add(net_with_pfxlen)

        fw_addrgrp_objs = forti_rest.get_collection("cmdb", "firewall", fw_addrgrp, vdom=vdom)
        logging.info(f"Expanding each Firewall {fw_addrgrp} by their Members' IP(s)")
        for addrgrp, member in fw_addrgrp_to_member_generator(fw_addrgrp_objs):
            member_ips = fw_addr_to_ips[member]
            fw_addr_to_ips[addrgrp].update(member_ips)

        ret.append(fw_addr_to_ips)
    return ret


def vdom_routing_tables(vdom: str, forti_rest: FortiConnect) -> List[ModPyTricia]:
    """
    Downloads & Stores VDOM's IPv4 and IPv6 routing-tables and return them as
    ModPyTricia objects (CIDR-Trie Data Structures).
    """

    ret = []
    for ip_bits, c_name in zip((32, 128), ("ipv4", "ipv6")):
        routing_table = ModPyTricia(ip_bits)
        logging.info(f"Downloading VDOM's {c_name} routing-table")
        rib_objs = forti_rest.get_collection("monitor", "router", c_name, vdom=vdom)
        logging.info(f"Parsing VDOM's {c_name} routing-table")
        for obj in rib_objs:
            route: str = obj["ip_mask"]
            intf: str = obj["interface"]
            routing_table.insert(route, intf)
        ret.append(routing_table)
    return ret


def download_firewall_policies(vdom: str, forti_rest: FortiConnect) -> List[Dict]:
    """Download Firewall Policies objects and return them"""

    logging.info("Downloading FW policies")
    return forti_rest.get_collection("cmdb", "firewall", "policy", vdom=vdom)


def parse_firewall_policies(
        policies_objs: List[Dict],
        fw_policies4: PolicyParser,
        fw_policies6: PolicyParser) -> List[Tuple]:
    """
    Iterates through each firewall policy object, classifies it (IPv4 or IPv6),
    then sends it to its appropriate parser. The parsers are generators which
    yield the actual results.

    Returns the results of the parsed policies after sorting them by Policy ID.
    """

    logging.info("Parsing FW Policies")
    parsed_policies = []
    for policy in policies_objs:
        if policy["srcaddr"]:
            for result4 in fw_policies4.parse(policy):
                parsed_policies.extend(result4)
        else:
            for result6 in fw_policies6.parse(policy):
                parsed_policies.extend(result6)
    return sorted(parsed_policies, key=lambda entry: entry[0])


def add_user_args() -> ArgumentParser:
    """Sets CLI arguments and returns the parser object"""

    parser = ArgumentParser()
    parser.add_argument("--username", help="Username", required=True)
    parser.add_argument("--device", help="Device Hostname/IP", required=True)
    parser.add_argument("--vdom", help="VDOM name", required=True)
    parser.add_argument("--intf", help="Interface name", required=True)
    parser.add_argument("--log", help="Enable info logging", required=False, action="store_true")
    return parser


def parse_user_args() -> Tuple[str, str, str, str, str, Optional[bool]]:
    """Parse loaded CLI arguments and return their values"""

    parser = add_user_args()
    parsed_args = parser.parse_args()

    username: str = parsed_args.username
    password: str = getpass("Password: ")
    device: str = parsed_args.device
    vdom: str = parsed_args.vdom
    target_intf: str = parsed_args.intf
    logging_status: Optional[bool] = parsed_args.log
    return username, password, device, vdom, target_intf, logging_status


def set_info_logging(logging_status: Optional[bool]) -> None:
    """Enable/Disable informational-level logging based on CLI argument"""

    if logging_status:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.disable()


def write_to_disk(parsed_policies: List, file_name: str) -> None:
    """Writes output to disk"""

    if parsed_policies:
        logging.info("Writing results to disk")
        with open(file_name, "w", encoding="utf-8") as output_file:
            csv_writer = csv.writer(output_file, delimiter=";", lineterminator="\n")
            # Write Header
            header = ["Policy ID", "IP Version", "Named Address", "IP Network", "Route", "Status"]
            csv_writer.writerow(header)
            # Write Rows
            for row in parsed_policies:
                csv_writer.writerow(row)
    else:
        logging.info("Provided interface is not referenced in any policy")


def main() -> None:
    """Main Function"""

    # Parse CLI args
    username, password, device, vdom, target_intf, logging_status = parse_user_args()

    # Enable/Disable informational-level logging
    set_info_logging(logging_status)

    # Disable warnings while sending HTTPS requests
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    with FortiConnect(username, password, device) as forti_rest:
        query_intf_in_vdom(target_intf, vdom, forti_rest)
        zones_to_intfs = map_zones_to_interfaces(vdom, forti_rest)
        fw_addr_to_ips4, fw_addr_to_ips6 = map_fw_addr_to_ips(vdom, forti_rest)
        routing_table4, routing_table6 = vdom_routing_tables(vdom, forti_rest)
        fw_policies_objs = download_firewall_policies(vdom, forti_rest)

    # Instantiate objects for parsing IPv4 and IPv6 firewll policies
    policy_parser4 = PolicyParser(target_intf, zones_to_intfs, fw_addr_to_ips4, routing_table4, "IPv4")
    policy_parser6 = PolicyParser(target_intf, zones_to_intfs, fw_addr_to_ips6, routing_table6, "IPv6")

    # Iterate through the downloaded FW policies and hand them to their apropriate parser
    parsed_policies = parse_firewall_policies(fw_policies_objs, policy_parser4, policy_parser6)

    # Write results to disk as a CSV file
    output_file_name = f"{device}_{vdom}_{target_intf}_result.csv"
    write_to_disk(parsed_policies, output_file_name)


if __name__ == "__main__":
    main()
