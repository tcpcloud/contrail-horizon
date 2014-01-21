# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
#    Copyright (c) 2013 Juniper Networks, Inc. All rights reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

class NetworkObject(object):
    def __init__(self, id, name, connectivity_summary, policy_summary,
                       ipam_summary, ip_blocks_summary, status):
        self.id                = id
        self.name              = name
        self.connectivity_summ = connectivity_summary
        self.pol_summ          = policy_summary
        self.ipam_summ         = ipam_summary
        self.ip_blocks_summ    = ip_blocks_summary
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_NETWORK_DATA = (
    NetworkObject('1', 'db-net', 'db-pol','proj3_con', 'ipam-cmn', '192.168.1.0...', 'Up'),
    NetworkObject('2', 'payment-net', 'payment-pol','None', 'ipam-cmn', '192.168.10.0', 'Up'),
    NetworkObject('3', 'dev-branch2', 'brnch-pol', 'None', 'ipam-brn2', '192.168.20.0', 'Up'),
    NetworkObject('4', 'ngnix-net', 'webserver-pol','None', 'ipam-cmn', '192.168.30.0', 'Up'),
    NetworkObject('5', 'middleware-net', 'db-pol','proj_3_con', 'ipam-cmn', '192.168.40.0', 'Up'),
    NetworkObject('6', 'test-team', 'test-pol','None', 'ipam-cmn', '192.168.50.0','Up'),
)

class NetworkObject2(object):
    def __init__(self, id, name, summary, descr, status):
        self.id                = id
        self.name              = name
        self.summ              = summary
        self.descr             = descr
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_NETWORK2_DATA = (
    NetworkObject2('1', 'db-net', '5 IP Blocks, 129 Instances', 'net for databases', 'Up'),
    NetworkObject2('2', 'payment-net', '2 IP Blocks, 254 Instances', 'net for payment apps', 'Up'),
    NetworkObject2('3', 'dev-branch2', '1 IP Blocks, 28 Instances', 'net for branch2','Up'),
    NetworkObject2('4', 'ngnix-net', '3 IP Blocks, 192 Instances', 'net for webservers','Up'),
)


class NetworkPortObject(object):
    def __init__(self, id, ip_address, instance_name, port, status):
        self.id                = id
        self.ip_address        = ip_address
        self.instance_name     = instance_name
        self.port              = port
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_NETPORT_DATA = (
    NetworkPortObject('1', '192.168.1.2', 'cloud-pipe_192','eth0', 'Up'),
    NetworkPortObject('2', '192.168.1.10', 'oracle-inst-sales','eth1', 'Up'),
    NetworkPortObject('3', '192.168.1.11', 'oracle-inst-logistics','eth1', 'Up'),
)

class NetworkPolicyObject(object):
    def __init__(self, id, name, assoc, status):
        self.id                = id
        self.name              = name
        self.assoc             = assoc
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_POLICY_DATA = (
    NetworkPolicyObject('1', 'db-net-policy', ' 6 rules, 4 attached networks, 129 instances','Up'),
    NetworkPolicyObject('2', 'branch2-policy', '3 rules, 7 attached networks, 113 instances','Up'),
    NetworkPolicyObject('3', 'payment-policy', '7 rules, 3 attached networks,  59 instances','Up'),
)

class NetworkConnectivityObject(object):
    def __init__(self, id, name, assoc, status):
        self.id                = id
        self.name              = name
        self.assoc             = assoc
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_NETCONN_DATA = (
    NetworkConnectivityObject('1', 'db-net-conn', 'db-net, ngnix-net, fake-net ...','Up'),
    NetworkConnectivityObject('2', 'branch2-conn', 'dev-branch2','Up'),
    NetworkConnectivityObject('3', 'payment-conn', 'payment-net','Up'),
)

class NetworkIpamObject(object):
    def __init__(self, id, name, ipam_type, assoc, status):
        self.id                = id
        self.name              = name
        self.ipam_type         = ipam_type
        self.assoc             = assoc
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_IPAM_DATA = (
    NetworkIpamObject('1', 'db-net-ipam', 'DHCP',
                      '12 IP Blocks in 6 Networks, 29 instances','Up'),
    NetworkIpamObject('2', 'sp-ipam', 'Fixed',
                      '17 IP Blocks in 9 Networks,  57 instances ','Up'),
    NetworkIpamObject('3', 'branch2-ipam', 'DHCP',
                      '3 IP Blocks in 2 Networks, 11 instances','Up'),
    NetworkIpamObject('4', 'payment-ipam', 'Fixed',
                      '5 IP Blocks in 5 Networks, 28 instances','Up'),
)

class PolicyNetObject(object):
    def __init__(self, id, name, status):
        self.id                = id
        self.name              = name
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_POLICYNET_DATA = (
    PolicyNetObject('1', 'db-net-policy', 'Up'),
    PolicyNetObject('3', 'payment-policy', 'Up'),
)

class ConnectivityNetObject(object):
    def __init__(self, id, name, status):
        self.id                = id
        self.name              = name
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_CONNET_DATA = (
    ConnectivityNetObject('1', 'db-net-conn', 'Up'),
    ConnectivityNetObject('3', 'payment-conn', 'Up'),
)

class IpamNetObject(object):
    def __init__(self, id, name, status):
        self.id                = id
        self.name              = name
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)

TEST_IPAMNET_DATA = (
    IpamNetObject('1', 'db-net-ipam','Up'),
    IpamNetObject('4', 'payment-ipam', 'Up'),
)

class IpBlockNetObject(object):
    def __init__(self, id, ip_addr, ipam, ipam_type, inst_count, free_addr):
        self.id         = id
        self.ip_addr    = ip_addr
        self.ipam       = ipam
        self.ipam_type  = ipam_type
        self.inst_count = inst_count
        self.free_addr  = free_addr

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)

TEST_IP_BLOCKNET_DATA = (
    IpBlockNetObject('1', '192.168.1.0', 'Fixed : db-net-ipam', 'Fixed', '39', '12'),
    IpBlockNetObject('2', '192.168.2.0', 'Fixed : db-net-ipam', 'Fixed', '9', '29'),
    IpBlockNetObject('3', '192.168.3.0', 'DHCP : db-net-ipam', 'DHCP', '1', '32' ),
    IpBlockNetObject('4', '192.168.4.0', 'Fixed : payment-net-ipam', 'Fixed', '2', '22'),
    IpBlockNetObject('5', '192.168.20.0', 'DHCP : payment-net-ipam', 'DHCP', '9', '39'),
    IpBlockNetObject('6', '192.168.30.0', 'DHCP : db-net-ipam', 'DHCP', '9', '240'),
    IpBlockNetObject('7', '192.168.40.0', 'DHCP : dbnet-ipam', 'DHCP', '23', '220'),
)

class ConnPolicyNetObject(object):
    def __init__(self, id, conn, policy):
        self.id     = id
        self.conn   = conn
        self.policy = policy

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)

TEST_IP_CONNPOLICYNET_DATA = (
    ConnPolicyNetObject('1', 'db-net-conn', 'db-net-policy'),
)

class IpamRowObject(object):
    def __init__(self, id, ip_option, value):
        self.id         = id
        self.ip_option  = ip_option
        self.value      = value

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)

TEST_IPAMROW_DATA = (
    IpamRowObject('1', 'DNS', '8.8.8.8'),
    IpamRowObject('2', 'DNS', '2.2.2.2'),
    IpamRowObject('4', 'NTP', '192.168.1.1'),
)

class IpamNetObject(object):
    def __init__(self, id, name, ipam_summary, status):
        self.id                = id
        self.name              = name
        self.ipam_summ         = ipam_summary
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_IPAM_NET_DATA = (
    IpamNetObject('1', '192.168.2.0/24', 'db-net', 'Up'),
    IpamNetObject('2', '192.168.3.0/24', 'payment-net', 'Up'),
    IpamNetObject('3', '192.168.40.0/24', 'ngnix-net', 'Up'),
)

class ConnEntryObject(object):
    def __init__(self, id, net_name, net_addr, dst_type, dest):
        self.id         = id
        self.net_name   = net_name
        self.net_addr   = net_addr
        self.dst_type   = dst_type
        self.dest       = dest

TEST_CONNROW_DATA = (
    ConnEntryObject('1', 'proj3:db-net', 'ALL', 'IP','10.8.8.8'),
    ConnEntryObject('2', 'Public', '10.6.250.0 / 24', 'VPN','10.8.8.2'),
    ConnEntryObject('3', 'Public', 'ALL', 'IP','10.8.8.254'),
)

class PolicyRuleDetailObject(object):
    def __init__(self, id, direction, summary, action_list, proto_or_app,
                 src_port, src_addr, dst_port, dst_addr, fake_net_for_assoc):
        self.id          = id
        self.direction   = direction
        self.summary     = summary
        self.action_list = action_list
        self.proto_or_app = proto_or_app
        self.src_port     = src_port
        self.src_addr     = src_addr
        self.dst_port     = dst_port
        self.dst_addr     = dst_addr
        self.net_assoc    = fake_net_for_assoc

TEST_POLRULE_DETAIL_DATA = (
    PolicyRuleDetailObject('1', 'Inbound TCP', 'TCP Traffic from 192.168.2.0/24 to Port 8080 for 192.168.3.0/24', 'Allow', 'TCP', 'Any',       '192.168.2.0/24',  '8080',        '192.168.3.0/24 : port 8080-8900, 9000', 'db-net'),
    PolicyRuleDetailObject('2', 'Outbound SMTP', 'TCP Traffic from db-net for SMTP to payment-net','Allow', 'TCP', 'Any',          'db-net',         'SMTP',        'all networks'        ,    'payment-net'),
    PolicyRuleDetailObject('3', 'Inbound HTTP apps', 'HTTP Services from Public Networks to ngnix-net', 'Allow', 'TCP', 'Any',      'Public network ',         'HTTP',        'ngnix-net'  ,    'uninor-net'),
    PolicyRuleDetailObject('4', 'Inbound oracle apps', 'oracle-apps services from project3:payment-net to db-net','Allow', 'TCP', 'Any', 'payment-net',    'oracle-apps', 'db-net', 'voda-net'),
    PolicyRuleDetailObject('5', 'Outbound', 'IP traffic from 192.168.2.0/24 to proj3:payment-net via gw-con', 'Gateway : gw1', 'TCP', 'Any',         '192.168.2.0/24', '8080',        'proj3:pay-net',  'dev-branch2'),
)

class NetworkPolicyNetObject(object):
    def __init__(self, id, name, policy_summary, status):
        self.id                = id
        self.name              = name
        self.pol_summ          = policy_summary
        self.status            = status

    def __repr__(self):
        return "<%s: %s>" % (self.__class__.__name__, self.name)


TEST_NETWORKPOLICY_NET_DATA = (
    NetworkPolicyNetObject('1', 'db-net', '129 instances in db-net using this policy', 'Up'),
    NetworkPolicyNetObject('2', 'payment-net', '57 instances in payment-net using this policy', 'Up'),
    NetworkPolicyNetObject('3', 'dev-branch2', '82 instances in dev-branch2 using this policy', 'Up'),
    NetworkPolicyNetObject('4', 'ngnix-net','28 instances and 3 other Network Policies' , 'Up'),
    NetworkPolicyNetObject('5', 'middleware-net', '72 instances and 4 other Network Policies', 'Up'),
    NetworkPolicyNetObject('6', 'test-team', '63 instances and 2 other Network Policies','Up'),
)

