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

from __future__ import absolute_import

import logging
import pdb

from netaddr import *
from neutronclient.v2_0 import client as neutron_client
from django.utils.datastructures import SortedDict

from openstack_dashboard.api.base import APIDictWrapper, url_for

from openstack_dashboard.api.neutron import *

LOG = logging.getLogger(__name__)


class ExtensionsContrailNet(NeutronAPIDictWrapper):
    """Wrapper for contrail neutron Networks"""
    _attrs = ['name', 'id', 'subnets', 'tenant_id', 'status',
              'admin_state_up', 'shared', 'contrail:instance_count',
              'contrail:policys', 'contrail:subnet_ipam']

    def __init__(self, apiresource):
        apiresource['free_ip'] = 0
        if not 'contrail:subnet_ipam' in apiresource.keys():
            apiresource['contrail:subnet_ipam'] = []
        else:
            for s in apiresource['contrail:subnet_ipam']:
                apiresource['free_ip'] += \
                    (IPNetwork(s['subnet_cidr']).size - 3 - \
                     int(apiresource['contrail:instance_count']))
        apiresource['state'] = \
            'Up' if apiresource['admin_state_up'] else 'Down'
        if not 'contrail:policys' in apiresource.keys():
            apiresource['contrail:policys'] = []
        apiresource['net_policies'] = apiresource['contrail:policys']
        apiresource['summary'] = \
            "{0} IP Blocks, {1} attached policies".format(
            len(apiresource['subnets']),
            len(apiresource['net_policies']))

        super(ExtensionsContrailNet, self).__init__(apiresource)


def network_summary(request, **params):
    LOG.debug("network_summary(): params=%s" % (params))
    networks = neutronclient(request).list_networks(**params).get('networks')
    return [ExtensionsContrailNet(n) for n in networks]


def network_summary_for_tenant(request, tenant_id, **params):
    """Return a network summary list available for the tenant.
    The list contains networks owned by the tenant and public networks.
    If requested_networks specified, it searches requested_networks only.
    """
    LOG.debug("network_summary_for_tenant(): tenant_id=%s, params=%s"
              % (tenant_id, params))

    # If a user has admin role, network list returned by Neutron API
    # contains networks that do not belong to that tenant.
    # So we need to specify tenant_id when calling network_list().
    networks = network_summary(request, tenant_id=tenant_id,
                               shared=False, **params)

    return networks


def network_summary_get(request, network_id, **params):
    LOG.debug("network_summary_get(): netid=%s, params=%s" %
              (network_id, params))
    network = neutronclient(request).show_network(network_id,
                                                  **params).get('network')
    return ExtensionsContrailNet(network)


class ExtensionsContrailIPBlock(NeutronAPIDictWrapper):
    """Wrapper for contrail neutron IP Blocks"""
    _attrs = ['name', 'enable_dhcp', 'network_id', 'tenant_id','gateway_ip'
              'contrail:ipam_fq_name','allocation_pools', 'ip_version',
              'cidr', 'contrail:instance_count', 'id']

    def __init__(self, apiresource):
        apiresource['inst_count'] = apiresource['contrail:instance_count']
        apiresource['ipam'] = apiresource['contrail:ipam_fq_name'][2]
        apiresource['summary'] = \
            "IPv{0} addressing, {1} instances assigned IPs".format(
            apiresource['ip_version'],
            apiresource['contrail:instance_count'])
        apiresource['addr_type'] = \
            'Dhcp' if apiresource['enable_dhcp'] else 'Fixed'
        super(ExtensionsContrailIPBlock, self).__init__(apiresource)


def ip_block_summary(request, **params):
    LOG.debug("ip_block_summary(): params=%s" % (params))
    ip_blocks = neutronclient(request).list_subnets(**params).get('subnets')
    return [ExtensionsContrailIPBlock(i) for i in ip_blocks]


class ExtensionsContrailNetInstances(NeutronAPIDictWrapper):
    """Wrapper for contrail neutron instances for a network"""
    _attrs = ['name', 'id', 'network_id', 'tenant_id',
              'admin_state_up','status', 'fixed_ips'
              'mac_address', 'device_id']


    def __init__(self, apiresource):
        apiresource['ip'] = []
        if 'fixed_ips' in apiresource.keys() and len(apiresource['fixed_ips']):
            apiresource['ip'] = apiresource['fixed_ips']
        apiresource['inst_name'] = apiresource['device_id']
        apiresource['state'] = \
            'Up' if apiresource['admin_state_up'] else 'Down'
        super(ExtensionsContrailNetInstances, self).__init__(apiresource)


def net_instances_summary(request, **params):
    LOG.debug("net_instances_summary(): params=%s" % (params))
    instances = neutronclient(request).list_ports(**params).get('ports')
    return [ExtensionsContrailNetInstances(i) for i in instances]


class ExtensionsContrailIpam(NeutronAPIDictWrapper):
    """Wrapper for contrail neutron ipam"""
    _attrs = ['name', 'id', 'mgmt', 'tenant_id']

    def __init__(self, apiresource):
        if 'mgmt' not in apiresource.keys() or \
            apiresource['mgmt'] == None:
            apiresource['mgmt'] = {'dhcp_option_list':{'dhcp_option':[]}}
        if 'ipam_method' in apiresource['mgmt'].keys():
           apiresource['addr_type'] = \
                'DHCP' if apiresource['mgmt']['ipam_method'] == 'dhcp' else 'Fixed'
        else:
            apiresource['addr_type'] = "Unknown"
        if not 'dhcp_option_list' in apiresource['mgmt'].keys():
            apiresource['mgmt'] = {'dhcp_option_list':{'dhcp_option':[]}}
        apiresource['summary'] = \
            "{0} IP Blocks in {1} networks, {2} instances".format('xx',
                                                               'yy','zz')
        super(ExtensionsContrailIpam, self).__init__(apiresource)


def ipam_summary(request, **params):
    LOG.debug("ipam_summary(): params=%s" % (params))
    ipams = neutronclient(request).list_ipams(**params).get('ipams')
    return [ExtensionsContrailIpam(n) for n in ipams]


def ipam_summary_for_tenant(request, tenant_id, **params):
    """Return a ipam summary list available for the tenant.
    The list contains ipams owned by the tenant.
    If requested_ipams specified, it searches requested_ipams only.
    """
    LOG.debug("ipam_summary_for_tenant(): tenant_id=%s, params=%s"
              % (tenant_id, params))

    ipams = ipam_summary(request, tenant_id=tenant_id, **params)

    return ipams


def ipam_show(request, ipam_id, **params):
    """Return an IPAM object with the requested id.
    """
    LOG.debug("ipam_show(): id = %s, params=%s" % (ipam_id, params))
    ipam = neutronclient(request).show_ipam(ipam_id, **params).get('ipam')

    return ExtensionsContrailIpam(ipam)


def ipam_create(request, name, **kwargs):
    """
    Create an ipam.
    { 'name': 'foo',
      'mgmt': {'ipam_method': 'dhcp|fixed',
               'dhcp_option_list': {
                                     'dhcp_option': 
                                         [{'dhcp_option_name': 'opt_1',
                                           'dhcp_option_value': 'opt_1_value'},
                                          {'dhcp_option_name': 'opt_1',
                                           'dhcp_option_value': 'opt_1_value'}]
                                   }
              }
    }
    :param request: request context
    :param name: name of the ipam to be created
    :param tenant_id: (optional) tenant id of the ipam to be created
    :param mgmt['ipam_method'] : dhcp or fixed 
    :returns: ExtensionsContrailIpam object
    """
    LOG.debug("ipam_create(): name=%s, kwargs=%s" % (name, kwargs))
    body = {'ipam':
                {'name': name}}
    body['ipam'].update(kwargs)
    ipam = neutronclient(request).create_ipam(body=body).get('ipam')
    return ExtensionsContrailIpam(ipam)


def ipam_modify(request, ipam_id, **kwargs):
    LOG.debug("ipam_modify(): ipam-id=%s, kwargs=%s" % (ipam_id, kwargs))
    body = {'ipam': kwargs}
    ipam = neutronclient(request).update_ipam(ipam_id,
                                              body=body).get('ipam')
    return ExtensionsContrailIpam(ipam)


def ipam_delete(request, ipam_id):
    LOG.debug("ipam_delete(): ipam-id=%s" % ipam_id)
    neutronclient(request).delete_ipam(ipam_id)

class ExtensionsContrailPolicy(NeutronAPIDictWrapper):
    """Wrapper for contrail neutron network policies"""
    _attrs = ['name', 'fq_name', 'id', 'entries', 'tenant_id', 'nets_using']

    def __init__(self, apiresource):
        super(ExtensionsContrailPolicy, self).__init__(apiresource)
        if (apiresource['entries'] == None) \
            or (apiresource['entries']['policy_rule'] == None):
            apiresource['entries'] = {}
            apiresource['entries']['policy_rule'] = []
            apiresource['rule_count'] = 0
        else:
            apiresource['rule_count'] = len(apiresource['entries']['policy_rule'])

        if 'nets_using' in apiresource.keys():
            apiresource['policy_net_ref_cnt'] = len(apiresource['nets_using'])
        else:
            apiresource['nets_using'] = []
            apiresource['policy_net_ref_cnt'] = 0
        apiresource['summary'] = \
            "Policy contains {0} rules and it is attached to " \
            "{1} networks".format(apiresource['rule_count'],
                                 apiresource['policy_net_ref_cnt'])
        i = 1
        for rule in apiresource['entries']['policy_rule']:
            rule['rule_sequence'] = {}
            rule['rule_sequence']['major'] = i
            rule['rule_sequence']['minor'] = 0
            i = i + 1

def policy_summary(request, **params):
    LOG.debug("policy_summary(): params=%s" % (params))
    policies = neutronclient(request).list_policys(**params).get('policys')
    return [ExtensionsContrailPolicy(p) for p in policies]


def policy_summary_for_tenant(request, tenant_id, **params):
    """Return a policy summary list available for the tenant.
    The list contains policies owned by the tenant.
    If requested_policys specified, it searches requested_policys only.
    """
    LOG.debug("policy_summary_for_tenant(): tenant_id=%s, params=%s"
              % (tenant_id, params))
    policies = policy_summary(request, tenant_id=tenant_id, **params)
    return policies


def policy_create(request, name, **kwargs):
    """
    Create a Network Policy.
    :param request: request context
    :param name: name of the network policy to be created
    :param tenant_id: (optional) tenant id of the ipam to be created
    :returns: ExtensionsContrailPolicy object
    """
    LOG.debug("policy_create(): name=%s, kwargs=%s" % (name, kwargs))
    body = {'policy': {'name': name,
              'entries': {}}}
    policy = neutronclient(request).create_policy(body=body).get('policy')
    return ExtensionsContrailPolicy(policy)


def policy_delete(request, policy_id):
    LOG.debug("policy_delete(): policy-id=%s" % policy_id)
    neutronclient(request).delete_policy(policy_id)

def policy_show(request, policy_id, **params):
    LOG.debug("policy_summary_get(): pol-id=%s, params=%s" %
              (policy_id, params))
    policy = neutronclient(request).show_policy(policy_id,
                                                  **params).get('policy')
    return ExtensionsContrailPolicy(policy)

def policy_modify(request, policy_id, **kwargs):
    LOG.debug("policy_modify(): policy-id=%s, kwargs=%s" % (policy_id, kwargs))
    body   = {'policy': kwargs}
    policy = neutronclient(request).update_policy(policy_id,
                                              body=body).get('policy')
    return ExtensionsContrailPolicy(policy)

