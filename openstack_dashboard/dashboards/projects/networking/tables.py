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

import logging

from django import shortcuts
from django.core import urlresolvers
from django.core.urlresolvers import reverse
from django.utils.translation import ugettext_lazy as _

from openstack_dashboard.api.neutron import *
from contrail_openstack_dashboard.openstack_dashboard.api.contrail_quantum import *
from openstack_dashboard.dashboards.project import dashboard
from horizon import tables
from horizon import exceptions

LOG = logging.getLogger(__name__)

def get_networks_tab_group_url(tab_name):
    return reverse("horizon:project:networking:index") + \
        "?tab=tab_group__" + tab_name + "_tab_table"

class CheckNetworkEditable(object):
    """Mixin class to determine the specified network is editable."""

    def allowed(self, request, datum=None):
        # Only administrator is allowed to create and manage shared networks.
        if datum and datum.shared:
            return False
        return True

class NetFilterAction(tables.FilterAction):
    def filter(self, table, networks, filter_string):
        net = filter_string.lower()

        def comp(networks):
            if any([net in (networks.name or "").lower()]):
                return True
            return False

        return filter(comp, networks)

class DeleteNet(CheckNetworkEditable, tables.DeleteAction):
    data_type_singular = _("Network")
    data_type_plural = _("Networks")

    def get_success_url(self, request):
        return get_networks_tab_group_url("networks")

    def delete(self, request, network_id):
        try:
            # Retrieve existing subnets belonging to the network.
            subnets = subnet_list(request, network_id=network_id)
            LOG.debug('Network %s has ip blocks: %s' %
                      (network_id, [s.id for s in subnets]))
            for s in subnets:
                subnet_delete(request, s.id)
                LOG.debug('Deleted ip block %s' % s.id)

            network_delete(request, network_id)
            LOG.debug('Deleted network %s successfully' % network_id)
        except:
            msg = _('Failed to delete network %s') % network_id
            LOG.info(msg)
            redirect = get_networks_tab_group_url("networks")
            exceptions.handle(request, msg, redirect=redirect)
    
class CreateNet(tables.LinkAction):
    name = "create" 
    verbose_name = _("Create Network")
    url = "horizon:project:networking:create_network"
    classes = ("ajax-modal", "btn-create")

class ModifyNetAssoc(CheckNetworkEditable, tables.LinkAction):
    name = "edit_policy"
    verbose_name = _("Edit Policy")
    url = "horizon:project:networking:modify_net_assoc"
    classes = ("ajax-modal", "btn-edit")

class EditIPBlocks(CheckNetworkEditable, tables.LinkAction):
    name = "edit_ip_blocks"
    verbose_name = _("Edit IP Blocks")
    url = "horizon:project:networking:edit_ip_block"
    classes = ("ajax-modal", "btn-edit")

class NetworksTable(tables.DataTable):
    name = tables.Column("name", verbose_name=_("Network"),
                         link=('horizon:project:networking:network_detail'))
    summ = tables.Column("summary", verbose_name=_("Summary"))
    shared = tables.Column("shared", verbose_name=_("Shared"))
    status = tables.Column("state", verbose_name=_("Status"))

    class Meta:
        name = "networks"
        verbose_name = _("Networks")
        table_actions = (NetFilterAction, CreateNet, DeleteNet)
        row_actions = (EditIPBlocks, ModifyNetAssoc, DeleteNet)

####### End Network, move to networks/tables.py

class PolicyFilterAction(tables.FilterAction):
    def filter(self, table, policy, filter_string):
        q = filter_string.lower()

        def comp(policy):
            if any([q in (policy.name or "").lower()]):
                return True
            return False

        return filter(comp, policy)


class DeletePolicy(tables.DeleteAction):
    data_type_singular = _("Policy")
    data_type_plural = _("Policy")

    def get_success_url(self, request):
        return get_networks_tab_group_url("policy")

    def delete(self, request, policy_id):
        try:
            policy_delete(request, policy_id)
            LOG.debug('Deleted policy %s' % policy_id)
        except:
            msg = _('Failed to delete policy %s') % policy_id
            LOG.info(msg)
            redirect = get_networks_tab_group_url("policy")
            exceptions.handle(request, msg, redirect=redirect)


class CreatePolicy(tables.LinkAction):
    name = "create_policy" 
    verbose_name = _("Create Policy")
    url = "horizon:project:networking:create_policy"
    classes = ("ajax-modal", "btn-create")


class EditPolicy(tables.LinkAction):
    name = "edit_policy"
    verbose_name = _("Edit Rules")
    url = "horizon:project:networking:edit_policy_rules"
    classes = ("ajax-modal", "btn-edit")


class PolicyTable(tables.DataTable):
    name = tables.Column("name", verbose_name=_("Network Policy"),
                         link=('horizon:project:networking:policy_detail'))
    assoc = tables.Column("summary", verbose_name=_("Summary"))


    def sanitize_id(self, obj_id):
        return obj_id


    class Meta:
        name = "policy"
        verbose_name = _("Network Policy")
        table_actions = (PolicyFilterAction, CreatePolicy, DeletePolicy)
        row_actions = (EditPolicy, DeletePolicy)

####### End policy, move to policy/tables.py

class IpamFilterAction(tables.FilterAction):
    def filter(self, table, ipam, filter_string):
        q = filter_string.lower()

        def comp(ipam):
            if any([q in (ipam.name or "").lower()]):
                return True
            return False

        return filter(comp, ipam)


class DeleteIpam(tables.DeleteAction):
    data_type_singular = _("IPAM")
    data_type_plural = _("IPAMs")

    def get_success_url(self, request):
        return get_networks_tab_group_url("ipam")

    def delete(self, request, ipam_id):
        try:
            ipam_delete(request, ipam_id)
            LOG.debug('Deleted ipam %s' % ipam_id)
        except:
            msg = _('Failed to delete ipam %s') % ipam_id
            LOG.info(msg)
            redirect = get_networks_tab_group_url("ipam")
            exceptions.handle(request, msg, redirect=redirect)


class CreateIpam(tables.LinkAction):
    name = "create_ipam" 
    verbose_name = _("Create IPAM")
    url = "horizon:project:networking:create_ipam"
    classes = ("ajax-modal", "btn-create")


class EditIpam(tables.LinkAction):
    name = "edit_ipam"
    verbose_name = _("Edit IPAM")
    url = 'horizon:project:networking:edit_ipam_entries'
    classes = ("ajax-modal", "btn-edit")


class IpamTable(tables.DataTable):
    name      = tables.Column("name", verbose_name=_("IPAM"),
                         link=('horizon:project:networking:ipam_detail'))


    class Meta:
        name = "ipam"
        verbose_name = _("IPAM")
        table_actions = (IpamFilterAction, CreateIpam, DeleteIpam)
        row_actions = (EditIpam, DeleteIpam)

####### End Network Landing page, move to networks/tables.py
class NetPolicyFilterAction(tables.FilterAction):
    def filter(self, table, policy, filter_string):
        q = filter_string.lower()

        def comp(policy):
            if any([q in (policy.name or "").lower()]):
                return True
            return False

        return filter(comp, policy)

class NetPolicyTable(tables.DataTable):
    name   = tables.Column("name", verbose_name=_("Network Policy"))

    def get_object_name(self, net_pol):
        return net_pol['id']

    def get_object_id(self, net_pol):
        return net_pol['id']


    class Meta:
        name = "net_pol"
        verbose_name = _("Policies attached to this Network")
        table_actions = (NetPolicyFilterAction, )
        multi_select = False

class NetInstancesFilterAction(tables.FilterAction):
    def filter(self, table, instances, filter_string):
        q = filter_string.lower()

        def comp(instances):
            if any([q in (instances.name or "").lower()]):
                return True
            return False

        return filter(comp, instances)


def get_free_addr_from_pools(ip_block):
    return IPNetwork(ip_block['cidr']).size - 3 - int(ip_block['inst_count'])


def get_pool_for_ip_block(ip_block):
    pool     = ip_block['allocation_pools']
    pool_str = ''
    for p in pool:
        pool_str += " {0} to {1}".format(p['start'], p['end'])
    return pool_str


def get_instance_ip_addr(instance):
    ip_addr = ''
    for i in instance['ip']:
        ip_addr += i['ip_address']
    return ip_addr


def get_port_and_status(port):
    return port['id'] + " is "+ port['status']

def get_instance_url(port):
    view = "horizon:project:instances:detail"
    if port.inst_name:
        return urlresolvers.reverse(view, args=(port.inst_name,))
    else:
        return None

class NetInstancesTable(tables.DataTable):
    port     = tables.Column(get_port_and_status, verbose_name=_("Port"))
    ip       = tables.Column(get_instance_ip_addr, verbose_name=_("Fixed IPs"))
    mac      = tables.Column("mac_address", verbose_name=_("Mac"))
    instance = tables.Column("inst_name",
                             link=get_instance_url,
                             verbose_name=_("Instance / Router"),
                             empty_value="-")

    def sanitize_id(self, obj_id):
        return int(obj_id)

    class Meta:
        name = "net_instances"
        verbose_name = _("Ports")
        table_actions = (NetInstancesFilterAction, )
        multi_select = False


class NetIpBlockFilterAction(tables.FilterAction):
    def filter(self, table, ip_block, filter_string):
        q = filter_string.lower()

        def comp(ip_block):
            if any([q in (ip_block.addr or "").lower()]):
                return True
            return False

        return filter(comp, ip_block)

class NetIpBlockTable(tables.DataTable):
    cidr      = tables.Column("cidr", verbose_name=_("IP Block"))
    pool      = tables.Column(get_pool_for_ip_block, verbose_name=_("IP Range"))
    gateway   = tables.Column("gateway_ip", verbose_name=_("Gateway"))
    ipam      = tables.Column("ipam", verbose_name=_("IP Options"))


    def sanitize_id(self, obj_id):
        return int(obj_id)


    class Meta:
        name = "net_ip_block"
        verbose_name = _("IP Blocks in the Network")
        table_actions = (NetIpBlockFilterAction, )
        multi_select = False

#Edit IPAM Options
def get_ipam_option(ipam_option):
    options_string = {}
    options_string [6]  = "DNS Server"
    options_string [4]  = "NTP Server"
    options_string [15] = "Domain Name"

    try:
        if options_string[int(ipam_option['dhcp_option_name'])]:
            return options_string[int(ipam_option['dhcp_option_name'])]
    except:
        return ipam_option['dhcp_option_name']

    return ipam_option['dhcp_option_name']


class DeleteIpamEntry(tables.DeleteAction):
    data_type_singular = _("IP Option")
    data_type_plural = _("IP Options")

    def get_success_url(self, request):
        return get_networks_tab_group_url("ipam")

#Use API to do actual delete 
    def delete(self, request, ipam_entry_id):
        redirect = get_networks_tab_group_url("ipam")
        ipam_key  = ipam_entry_id.split(":-")
        try:
            ipam_obj = ipam_show(request, ipam_id=ipam_key[0])
            ipam_del  = {'dhcp_option_name':ipam_key[1],
                         'dhcp_option_value': ipam_key[2]}
            ipam_obj['mgmt']['dhcp_option_list']['dhcp_option'].remove(ipam_del)
            ipam_update_dict = ipam_obj.__dict__['_apidict']['mgmt']
            try:
                ipam = ipam_modify(request,
                                   ipam_id=ipam_key[0], mgmt=ipam_update_dict)
                LOG.debug('Successfully deleted ip option: %s'
                          % unicode(ipam_del['dhcp_option_value']))
                return ipam
            except:
                ipam = []
                exceptions.handle(request,
                                  _('Unable to delete options to IPAM.'),
                                  redirect=redirect)
        except:
            ipam = []
            exceptions.handle(request,
                              _('Unable to delete options to IPAM.'),
                              redirect=redirect)


class IpamEntryTable(tables.DataTable):
    option = tables.Column(get_ipam_option, verbose_name=_("IP Option"))
    values = tables.Column("dhcp_option_value", verbose_name=_("Value"))


    def get_object_display(self, ipam_options):
        return str("Option {0} {1}".format(ipam_options['dhcp_option_name'],
                              ipam_options['dhcp_option_value']))


    def get_object_name(self, ipam_options):
        return str("Option {0} {1}".format(ipam_options['dhcp_option_name'],
                              ipam_options['dhcp_option_value']))


    def get_object_id(self, ipam_options):
        return ipam_options['id']


    class Meta:
        name = "ipam_entry"
        verbose_name = _("IP Options")
        table_actions = (DeleteIpamEntry,)
        row_actions = (DeleteIpamEntry,)


#IPAM Options Details
class IpamDetailTable(tables.DataTable):
    ip_option = tables.Column(get_ipam_option, verbose_name=_("IP Option"))
    value = tables.Column("dhcp_option_value", verbose_name=_("Value"))

    def get_object_display(self, ipam_options):
        return str("Option {0} {1}".format(ipam_options['dhcp_option_name'],
                              ipam_options['dhcp_option_value']))


    def get_object_name(self, ipam_options):
        return str("Option {0} {1}".format(ipam_options['dhcp_option_name'],
                              ipam_options['dhcp_option_value']))


    def get_object_id(self, ipam_options):
        return ipam_options['id']


    class Meta:
        name = "ipam_detail"
        verbose_name = _("IP Options")

class IpamDetailNetAssocFilterAction(tables.FilterAction):
    def filter(self, table, nets, filter_string):
        q = filter_string.lower()

        def comp(ipam):
            if any([q in (options.net_assoc or "").lower()]):
                return True
            return False

        return filter(options.net_assoc, ipam_detail_net_assoc)

class IpamDetailNetAssocTable(tables.DataTable):
    net_assoc = tables.Column("name", verbose_name=_("IP Block"))
    net_ipam  = tables.Column("ipam_summ", verbose_name=_("Network"))

    def sanitize_id(self, obj_id):
        return int(obj_id)

    class Meta:
        name = "ipam_detail_net_assoc"
        verbose_name = _("Associated IP Blocks")
        table_actions = (IpamDetailNetAssocFilterAction, )
        multi_select = False

#Edit IP Blocks
class DeleteIPBlock(tables.DeleteAction):
    data_type_singular = _("IP Block")
    data_type_plural = _("IP Blocks")

    def delete(self, request, subnet_id):
        try:
            subnet_delete(request, subnet_id)
            LOG.debug('Deleted ip block.')
        except:
            msg = _('Failed to delete subnet %s') % subnet_id
            LOG.info(msg)
            redirect = get_networks_tab_group_url("networks")
            exceptions.handle(request, msg, redirect=redirect)


    def get_success_url(self, request):
        return get_networks_tab_group_url("networks")

 
class IPBlockTable(tables.DataTable):
    cidr      = tables.Column("cidr", verbose_name=_("Network Address"))
    gateway   = tables.Column("gateway_ip", verbose_name=_("Gateway"))
    ipam      = tables.Column("ipam", verbose_name=_("IP Options"))
    

    class Meta:
        name = "ip_block"
        verbose_name  = _("IP Blocks")
        table_actions = (DeleteIPBlock,)
        row_actions   = (DeleteIPBlock,)

#End Edit IP Blocks

#Begin Network Policy Details

#move to some utils
def policy_net_display(nets):
    net_disp_all = ''
    for net in nets:
        net_disp = ''
        if not net['security_group'] == None:
            net_disp += str(net['security_group'])
        if not net['subnet'] == None:
            net_disp += str(net['subnet']['ip_prefix']) + "/" + \
                        str(net['subnet']['ip_prefix_len'])
        if not net['virtual_network'] == None:
            net_disp += str(net['virtual_network'])
        net_disp_all += "[{0}]".format(net_disp.replace(":", " "))
    return net_disp_all


def policy_ports_display(ports):
    ports_str = ''
    if len(ports) == 1 and ports[0]['start_port'] == -1:
        ports_str += " port any"
    else:
        ports_str += " port"
        for p in ports:
           ports_str += " " + str(p['start_port'])
           if p['start_port'] != p ['end_port']:
               ports_str += "-" + str(p['end_port'])
           if not p == ports[-1]:
               ports_str += ","

    return ports_str

def format_policy_rule(rule):
    rule_display = ''
    if 'simple_action' in rule and rule['simple_action'] != None:
        rule_display += rule['simple_action']
    elif rule['action_list']:
        if rule['action_list']['simple_action']:
            rule_display += rule['action_list']['simple_action']

    if not len(rule['application']):
        rule_display += " protocol " + rule['protocol']
        rule_display += " network  " + policy_net_display(rule['src_addresses'])
        rule_display += policy_ports_display(rule['src_ports'])
        rule_display += " " + rule['direction']
        rule_display += " network  " + policy_net_display(rule['dst_addresses'])
        rule_display += policy_ports_display(rule['dst_ports'])

    if rule['action_list']:
        rule_display += " action "
        if rule['action_list']['gateway_name']:
            rule_display += rule['action_list']['gateway']
        if rule['action_list']['apply_service']:
            rule_display += "apply-service "
            for service in rule['action_list']['apply_service']:
                rule_display += " " + service
        if rule['action_list']['mirror_to']:
            rule_display += "mirror-to "
            rule_display += rule['action_list']['mirror_to']['analyzer_name']

    return rule_display

def format_policy_rule_sequence(rule):
    sequence = rule['rule_sequence']
    if sequence and len(sequence):
        return "{0}.{1}".format(sequence['major'], sequence['minor'])
    return "None"


class PolicyDetailFilterAction(tables.FilterAction):
    def filter(self, table, rule, filter_string):
        q = filter_string.lower()

        def comp(policy):
            if any([q in (rule.src_addr or "").lower()]):
                return True
            return False

        return filter(rule.src_addr, policy_detail)

#Display Policy Rules
class PolicyDetailTable(tables.DataTable):
    sequence = tables.Column(format_policy_rule_sequence, verbose_name=_("Sequence"))
    rule     = tables.Column(format_policy_rule, verbose_name=_("Rule Details"))


    def get_object_display(self, rules):
        return str(format_policy_rule_sequence(rules))

    def get_object_name(self, rules):
        return str(format_policy_rule_sequence(rules))

    def get_object_id(self, rules):
        return str(rules)


    class Meta:
        name = "policy_detail"
        verbose_name = _("Policy Rules Details")
        table_actions = (PolicyDetailFilterAction, )
        multi_select = False

class PolicyRuleDeleteAction(tables.Action):
    name = "Delete"
    verbose = _("Delete Rule")
    classes = ("btn-delete", "btn-danger")

    def single(self, table, request, rule_id):
        rule = table.get_object_by_id(rule_id)
        sequence_id = rule['rule_sequence']
        policy_id   = rule['policy_id']
        try:
            policy = policy_show(request, policy_id=policy_id)
            rules  = policy['entries']['policy_rule']
            for r in rules:
                if r['rule_sequence'] == sequence_id:
                    rules.remove(r)
                    break
            rules_dict = policy.__dict__['_apidict']['entries']
            pol    = policy_modify(request, policy_id=policy_id,
                                   entries=rules_dict)
        except:
            pol = []
            exceptions.handle(request,
                              _('Unable to modify policy %s.') % policy_id)
        return shortcuts.redirect(get_networks_tab_group_url("policy"))



#Edit Policy Rules, display
class PolicyRulesEditTable(tables.DataTable):
    sequence = tables.Column(format_policy_rule_sequence,
                             verbose_name=_("Id"))
    rule     = tables.Column(format_policy_rule, verbose_name=_("Rule Details"))


    def get_object_display(self, rules):
        return str(format_policy_rule_sequence(rules))


    def get_object_name(self, rules):
        return str(format_policy_rule_sequence(rules))


    def get_object_id(self, rules):
        return str(format_policy_rule_sequence(rules))


    class Meta:
        name = "policy_detail"
        verbose_name  = _("Policy Rules Details")
        table_actions = (PolicyDetailFilterAction,)
        row_actions   = (PolicyRuleDeleteAction,)
        multi_select  = False

def get_policy_net_refs(nets):
    return nets[2]


class PolicyDetailNetAssocFilterAction(tables.FilterAction):
    def filter(self, table, nets, filter_string):
        q = filter_string.lower()

        def comp(policy):
            if any([q in (rule.net_assoc or "").lower()]):
                return True
            return False

        return filter(nets.net_assoc, policy_detail_net_assoc)

class PolicyDetailNetAssocTable(tables.DataTable):
    net_assoc = tables.Column(get_policy_net_refs,
                              verbose_name=_("Associated Network"))


    def get_object_display(self, net):
        return unicode(str(net))


    def get_object_name(self, net):
        return str(net)


    def get_object_id(self, net):
        return str(net)

    class Meta:
        name = "policy_detail_net_assoc"
        verbose_name = _("Networks associated with this policy")
        table_actions = (PolicyDetailNetAssocFilterAction, )
        multi_select = False
