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

from django.core import validators
from django.core.urlresolvers import reverse
from django.forms import ValidationError
from django.utils.translation import ugettext_lazy as _

from openstack_dashboard.api.neutron import *
from openstack_dashboard.api.contrail_quantum import *
from openstack_dashboard.dashboards.project import dashboard
from horizon import exceptions
from horizon import forms
from horizon import messages
from tables import *
from horizon.utils import fields

ALLOCATE_IPAM_URL = "horizon:project:networking:create_ipam"

class AddIpamEntry(forms.SelfHandlingForm):
    option_code = forms.ChoiceField(label=_('Option Code'),
                                    choices=[('6', 'DNS Server'),
                                             ('15', 'Domain Name'),
                                             ('4', 'NTP Server')],
                                    help_text=_("IP options that should be"
                                                " supplied to instances"),
                                    widget=forms.Select(attrs={'class':
                                                               'switchable'}))
    option_value = forms.CharField(label=_("Option Value"),
                     help_text=_("Values for the chosen Option Code"))

    ipam_id = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super(AddIpamEntry, self).__init__(*args, **kwargs)


#Add Validations
    def clean(self):
        cleaned_data = super(AddIpamEntry, self).clean()
        option_code  = cleaned_data.get("option_code", None)
        option_value = cleaned_data.get("option_value", None)
        return cleaned_data

    def handle(self, request, data):
        redirect = get_networks_tab_group_url("ipam")
        try:
            ipam_obj = ipam_show(self.request, ipam_id=data['ipam_id'])
            ipam_entry = {'dhcp_option_name':data['option_code'],
                          'dhcp_option_value': data['option_value']}
            ipam_obj['mgmt']['dhcp_option_list']['dhcp_option'].append(ipam_entry)
            ipam_update_dict = ipam_obj.__dict__['_apidict']['mgmt']
            try:
                ipam = ipam_modify(request,
                                   ipam_id=data['ipam_id'], mgmt=ipam_update_dict)
                messages.success(request,
                                 _('Successfully added ip option: %s')
                                 % unicode(ipam_entry['dhcp_option_value']))
                return ipam
            except:
                ipam = []
                exceptions.handle(request,
                                  _('Unable to add option to IPAM.'),
                                  redirect=redirect)
        except:
            ipam = []
            exceptions.handle(request,
                              _('Unable to add option to IPAM.'),
                              redirect=redirect)


#Begin Create IPAM
class CreateIpam(forms.SelfHandlingForm):
    name = forms.CharField(label=_("Name"),
                           validators=[validators.validate_slug])

    description = forms.CharField(label=_("Description"),
                                  required = False)

    dns_server = fields.IPField(label=_("DNS Server"),
                                version=fields.IPv4 | fields.IPv6,
                                mask=False,
                                required = False,
                                help_text=_("Address of the DNS Server that "
                                           "will be used by Instances"))

    domain_name = forms.CharField(label=_("Domain Name"),
                                  required = False,
                                  help_text=_("Domain name that will be "
                                              "assigned to Instances"))

    ntp_server = fields.IPField(label=_("NTP Server (optional)"),
                                version=fields.IPv4 | fields.IPv6,
                                mask=False, required=False,
                                help_text=_("Address of the NTP Server that "
                                           "will be used by Instances"))

#add clean to validate

    def handle(self, request, data):
        redirect = get_networks_tab_group_url("ipam")
        #Use function to convert well-known options to text and vice-versa
        #Don't set dns, domain, ntp if they are unset

        params = {'name': data['name'],
                  'mgmt': {'ipam_method': 'dhcp',
                           'dhcp_option_list': {'dhcp_option':[]}}}

        if data['dns_server']:
            params['mgmt']['dhcp_option_list']['dhcp_option'].append(
                                                {'dhcp_option_name': '6',
                                                 'dhcp_option_value':
                                                  data['dns_server']})
        if data['domain_name']:
            params['mgmt']['dhcp_option_list']['dhcp_option'].append(
                                                {'dhcp_option_name': '15',
                                                 'dhcp_option_value':
                                                  data['domain_name']})

        if data['ntp_server']:
            params['mgmt']['dhcp_option_list']['dhcp_option'].append(
                                                {'dhcp_option_name': '4',
                                                 'dhcp_option_value':
                                                  data['ntp_server']})
        try:
            ipam = ipam_create(request, **params)
            messages.success(request,
                             _('Successfully created ipam: %s')
                               % data['name'])
            return ipam
        except:
            exceptions.handle(request,
                              _('Unable to create ipam.'),
                              redirect=redirect)

#End Create IPAM
#Begin Create Network Policy
class CreatePolicy(forms.SelfHandlingForm):
    name = forms.CharField(label=_("Name"),
                           validators=[validators.validate_slug])
    description = forms.CharField(label=_("Description"),
                                  required=False)


    def handle(self, request, data):
        tenant_id = self.request.user.tenant_id
        redirect = get_networks_tab_group_url("policy")
        try:
            policy = policy_create(request, name=data['name'])
            messages.success(request,
                             _('Successfully created network policy: %s')
                               % data['name'])
            return policy
        except:
            exceptions.handle(request,
                              _('Unable to create policy.'),
                              redirect=redirect)
#End Create Network Policy

#Begin Create Network
class CreateNetwork(forms.SelfHandlingForm):
    name = forms.CharField(label=_("Name"),
                           validators=[validators.validate_slug])

    description = forms.CharField(label=_("Description"),
                                  required= False)

    ip_block    = fields.IPField(label=_("IP Block (optional)"), required=False,
                                 help_text=_("i.e. 192.168.2.0/24,  "
                                 "this should be within the address space "
                                 "allocated for the Project"),
                                 version=fields.IPv4 | fields.IPv6,
                                 mask=True)

    ipam        = forms.DynamicTypedChoiceField(label=_("IPAM (optional)"),
                                 required=False,
                                 empty_value=None,
                                 add_item_link=ALLOCATE_IPAM_URL,
                                 help_text=_("Choose IPAM that will be "
                                             "associated with the IP Block"))

    gateway     = fields.IPField(label=_('Gateway (optional)'),
                                 version=fields.IPv4,
                                 mask=False,
                                 required=False,
                                 help_text=_("Gateway for this IP Block"))

 
    net_pol     = forms.MultipleChoiceField(label=_('Network Policy'),
                                 help_text=_("Choose Network Policy that will "
                                             "be associated with the Network"),
                                 required=False,
                                 widget=forms.CheckboxSelectMultiple())

 
    def __init__(self, *args, **kwargs):
        super(CreateNetwork, self).__init__(*args, **kwargs)
        #Fetch the ipam list and add to ipam options
        tenant_id = self.request.user.tenant_id
        try:
            ipams = ipam_summary_for_tenant(self.request, tenant_id)
            if ipams:
                ipam_choices = [(ipam.id, ipam.name)
                                 for ipam in ipams]
            else:
                ipam_choices = [('', 'Create a new IPAM')]
        except:
            ipam_choices = []
            exceptions.handle(self.request, _('Unable to retrieve ipam list'))
        self.fields['ipam'].choices = ipam_choices

        #Fetch the policy list and add to policy options
        try:
            policies = policy_summary_for_tenant(self.request, tenant_id)
            if policies:
                policy_choices = [("{0}:-{1}:-{2}".format(
                                 policy.fq_name[0], policy.fq_name[1],
                                 policy.fq_name[2]),policy.name)
                                 for policy in policies]
            else:
                policy_choices = []
        except:
            policy_choices = []
            exceptions.handle(self.request, _('Unable to retrieve policy list'))
        self.fields['net_pol'].choices = policy_choices

    def clean(self):
        cleaned_data = super(CreateNetwork, self).clean()
        name        = cleaned_data.get("name")
        description = cleaned_data.get("description")
        ipam        = cleaned_data.get("ipam")
        ip_block    = cleaned_data.get("ip_block")
        net_pol     = cleaned_data.get("net_pol")
        gateway     = cleaned_data.get("gateway")

        if ip_block and not ipam:
            msg = _('IP Block : Choose an IPAM')
            raise ValidationError(msg)

        if ip_block and IPNetwork(ip_block).size < 3:
            msg = _('IP Block : Choose valid network prefix '
                    'between 1-30 i.e. 192.168.1.0/24')
            raise ValidationError(msg)

        if ip_block and gateway and IPAddress(gateway) not in IPNetwork(ip_block):
            msg = _('IP Gateway : Choose a Gateway IP within the CIDR')
            raise ValidationError(msg)

        return cleaned_data


    def handle(self, request, data):
        tenant_id = self.request.user.tenant_id
        redirect = get_networks_tab_group_url("networks")
        try:
            policy_list = []
            for pol in data['net_pol']:
                policy_str  = pol.split(':-')
                pol_fq_name = [policy_str[0],
                               policy_str[1],
                               policy_str[2]]
                policy_list.append(pol_fq_name)
            params  = {'name': data['name'], 'contrail:policys': policy_list}
            network = network_create(request, **params)
            messages.success(request,
                             _('Successfully created network: %s')
                               % data['name'])

            if data['ip_block']:
                try:
                    ipam_obj = ipam_show(self.request, ipam_id=data['ipam'])
                    params = {'network_id': network.id,
                              'cidr': data['ip_block'],
                              'ip_version': 4,
                              'contrail:ipam_fq_name': ipam_obj.fq_name
                            }
                    if data['gateway']:
                        params['gateway_ip'] = data['gateway']
                    subnet_create(request, **params)
                except Exception:
                    exceptions.handle(request,
                                      _('Unable to create ip block.'),
                                      redirect=redirect)
            return network
        except:
            exceptions.handle(request,
                              _('Unable to create network.'),
                              redirect=redirect)

#End Create Network

#Begin Modify Network Associations
class ModifyNetAssoc(forms.SelfHandlingForm):
    name = forms.CharField(label=_("Network"),
                           widget=forms.TextInput(
                           attrs={'readonly': 'readonly'}),
                           validators=[validators.validate_slug])

    policys = forms.MultipleChoiceField(label=_('Network Policy'),
                           required=False,
                           widget=forms.CheckboxSelectMultiple(),
                           help_text=_("Choose Network Policy that will "
                                       "be associated with the Network"))

    net_id  = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        pols = kwargs['initial']['net_pol']
        super(ModifyNetAssoc, self).__init__(*args, **kwargs)
        tenant_id = self.request.user.tenant_id
        try:
            policies = policy_summary_for_tenant(self.request, tenant_id)
            if policies:
                policy_choices = [("{0}:-{1}:-{2}".format(
                                 policy.fq_name[0], policy.fq_name[1],
                                 policy.fq_name[2]),str(policy.name))
                                 for policy in policies]
            else:
                policy_choices = []
        except:
            policy_choices = []
            exceptions.handle(request, _('Unable to retrieve policy list'))
        initial_choices = []
        for p in policy_choices:
            for i in pols:
                if i[2] == p[1]:
                    initial_choices.append(p[0])

        self.fields['policys'].initial = initial_choices
        self.fields['policys'].choices = policy_choices


    def clean(self):
        cleaned_data = super(ModifyNetAssoc, self).clean()
        name    = cleaned_data.get("name")
        net_pol = cleaned_data.get("policys")

        return cleaned_data


    def handle(self, request, data):
        tenant_id = self.request.user.tenant_id
        redirect = get_networks_tab_group_url("policy")
        try:
            policy_list = []
            for pol in data['policys']:
                policy_str  = pol.split(':-')
                pol_fq_name = [policy_str[0],
                               policy_str[1],
                               policy_str[2]]
                policy_list.append(pol_fq_name)
            params  = {'contrail:policys': policy_list}
            network = network_modify(request,
                                     network_id=data['net_id'], **params)
            messages.success(request,
                             _('Successfully edited polices for network: %s')
                               % data['name'])
            return network
        except:
            exceptions.handle(request,
                             _('Unable to edit polices for network: %s')
                               % data['name'], redirect=redirect)

#End Network Associations

# Begin Create IP Blocks
class AddIPBlocks(forms.SelfHandlingForm):
    cidr    = fields.IPField(label=_('Address /  Prefix'),
                              version=fields.IPv4,
                              mask=True,
                              help_text=_("i.e. 192.168.2.0/24, this "
                                          "should be subset of the "
                                          "address space allocated for "
                                          "the Project."))
    ipam    = forms.DynamicTypedChoiceField(label=_("IPAM"),
                                 required=True,
                                 empty_value=None,
                                 add_item_link=ALLOCATE_IPAM_URL,
                                 help_text=_("Choose IPAM that will be "
                                             "associated with the IP Block"))
    gateway = fields.IPField(label=_('Gateway'),
                              version=fields.IPv4,
                              mask=False,
                              required=False,
                              help_text=_("Gateway for this network"))

    id      = forms.CharField(widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        ipams = kwargs.pop('ipams', [])
        super(AddIPBlocks, self).__init__(*args, **kwargs)
        tenant_id = self.request.user.tenant_id
        try:
            ipams = ipam_summary_for_tenant(self.request, tenant_id)
            if ipams:
                ipam_choices = [(ipam.id, ipam.name)
                                 for ipam in ipams]
            else:
                ipam_choices = [('', 'Create a new IPAM')]
        except:
            ipam_choices = []
            exceptions.handle(self.request, _('Unable to retrieve ipam list'))
        self.fields['ipam'].choices = ipam_choices

    def clean(self):
        cleaned_data = super(AddIPBlocks, self).clean()
        cidr    = cleaned_data.get("cidr")
        gateway = cleaned_data.get("gateway")
        ipam    = cleaned_data.get("ipam")
        id      = cleaned_data.get("id")

        if not ipam:
            msg = _('IP Block : Choose an IPAM')
            raise ValidationError(msg)

        if cidr and IPNetwork(cidr).size < 3:
            msg = _('IP Block : Choose valid network prefix '
                    'between 1-30 i.e. 192.168.1.0/24')
            raise ValidationError(msg)

        if gateway and IPAddress(gateway) not in IPNetwork(cidr):
            msg = _('IP Gateway : Choose a Gateway IP within the CIDR')
            raise ValidationError(msg)
        return cleaned_data


    def handle(self, request, data):
        redirect = get_networks_tab_group_url("networks")
        tenant_id = self.request.user.tenant_id
        try:
            ipam_obj = ipam_show(self.request, ipam_id=data['ipam'])
            params = {'network_id': data['id'],
                      'cidr': data['cidr'],
                      'ip_version': 4,
                      'contrail:ipam_fq_name': ipam_obj.fq_name
                     }
            if data['gateway']:
                params['gateway_ip'] = data['gateway']
            ip_block = subnet_create(request, **params)
            messages.success(request,
                             _('Successfully added IP Block %s')
                             % unicode(data['cidr']))
            return ip_block
        except:
            exceptions.handle(request,
                              _('Unable to add IP Block.'),
                              redirect=redirect)
#End Edit IP Block

#Begin Edit Policy Rules
class AddPolicyRules(forms.SelfHandlingForm):
    sequence_id = forms.ChoiceField(label=_('Sequence Id'),
                                    help_text=_("Choose the Sequence Id for "
                                                " this rule."))

    simple_action = forms.ChoiceField(label=_('Action'),
                                    choices=[('pass', 'Pass'),
                                             ('deny', 'Deny')],
                                    help_text=_("Actions that will be applied "
                                                " on the traffic that matches"
                                                " the rules"))
    direction = forms.ChoiceField(label=_('Direction'),
                                    choices=[('<>', '<> Bidirectional'),
                                             ('>', '> Unidirectional')],
                                    help_text=_("Direction of traffic on which"
                                                " the rule will be applied"))

    protocol = forms.ChoiceField(label=_('IP Protocol'),
                                    choices=[('any', 'ANY'),
                                             ('tcp', 'TCP'),
                                             ('udp', 'UDP'),
                                             ('icmp', 'ICMP')],
                                    help_text=_("TCP, UDP, ICMP or All protocols"))

    source_net = forms.ChoiceField(label=_('Source Net'),required=True,
                                   help_text=_("Network or Prefix Type"),
                                   initial="any")

    src_ports = forms.CharField(label=_("Source Ports"),required=False,
                                    help_text=_("Originating Port list i.e. "
                                                "80 or 80,443,8080,8443-8446"),
                                    initial="any")


    dst_net = forms.ChoiceField(label=_('Destination Net'),required=True,
                                help_text=_("Network or Prefix Type"),
                                initial="any")

    dst_ports = forms.CharField(label=_("Destination Ports"),required=False,
                                    help_text=_("Destination Port list i.e. "
                                                "80 or 80,443,8080,8443-8446"),
                                    initial="any")

    id = forms.CharField(widget=forms.HiddenInput(), required=False)


    def __init__(self, *args, **kwargs):
        super(AddPolicyRules, self).__init__(*args, **kwargs)

        net_list = [('any','ANY'),
                    ('local', 'LOCAL')]
        try:
            nets = network_summary(self.request)
            for n in nets:
                net_fq      = n['contrail:fq_name']
                net_fq_name = "{0}:{1}:{2}".format(net_fq[0],net_fq[1],net_fq[2])
                net_list.append((net_fq_name, net_fq_name))
            self.fields['source_net'].choices = net_list
            self.fields['dst_net'].choices = net_list
        except:
            self.fields['source_net'].choices = []
            self.fields['dst_net'].choices = []
            exceptions.handle(request, _('Unable to retrieve network list'))

        pol_id = kwargs['initial']['id']
        sequence_id_choices = [("last", "Last Rule"),
                               ("first", "First Rule")]
        try:
            pol_obj = policy_show(self.request, policy_id=pol_id)

            seq_list = []
            for rule in pol_obj['entries']['policy_rule']:
                seq_val = "after:{0}.{1}".format(rule['rule_sequence']['major'],
                                         rule['rule_sequence']['minor'])
                seq_val_lbl = "{0}.{1}".format(rule['rule_sequence']['major'],
                                         rule['rule_sequence']['minor'])
                seq_list.append((seq_val, seq_val_lbl))
            sequence_id_choices.append(('After Rule', seq_list))
        except:
            pol_obj = {}

        self.fields['sequence_id'].choices = sequence_id_choices
        

    def clean(self):
        cleaned_data = super(AddPolicyRules, self).clean()
        simple_action = cleaned_data.get("simple_action", None)
        direction     = cleaned_data.get("direction", None)
        protocol      = cleaned_data.get("protocol", None)
        src_ports     = cleaned_data.get("src_ports", None)
        source_net    = cleaned_data.get("source_net", None)
        dst_ports     = cleaned_data.get("dst_ports", None)
        dst_net       = cleaned_data.get("dst_net", None)
        sequence_id   = cleaned_data.get("sequence_id", None)

        return cleaned_data

    def handle(self, request, data):
        redirect = get_networks_tab_group_url("policy")
        policy_id = data['id']
        src_port_list = []
        if data['src_ports'] == 'any':
            sport = {'end_port': -1, 'start_port':-1}
            src_port_list.append(sport)
        elif len(data['src_ports']):
            src_port_str = data['src_ports'].split(',')
            for s in src_port_str:
                range_str = s.split('-')
                if len(range_str) == 2:
                    sport = {'end_port':int(range_str[1]),
                             'start_port':int(range_str[0])}
                elif len(range_str) == 1:
                    sport = {'end_port':int(range_str[0]),
                             'start_port':int(range_str[0])}
                src_port_list.append(sport)

        dst_port_list = []
        if data['dst_ports'] == 'any':
            dport = {'end_port': -1, 'start_port':-1}
            dst_port_list.append(dport)
        elif len(data['dst_ports']):
            dst_port_str = data['dst_ports'].split(',')
            for d in dst_port_str:
                drange_str = d.split('-')
                if len(drange_str) == 2:
                    dport = {'end_port':int(drange_str[1]),
                             'start_port':int(drange_str[0])}
                elif len(drange_str) == 1:
                    dport = {'end_port':int(drange_str[0]),
                             'start_port':int(drange_str[0])}
                dst_port_list.append(dport)

        try:
           policy_obj = policy_show(request, policy_id=policy_id)
           rule = {'direction': data['direction'],
                   'protocol': data['protocol'],
                   'src_addresses':[{
                                     'security_group' : None,
                                     'subnet': None,
                                     'virtual_network': data['source_net']
                                   }],
                   'dst_addresses':[{
                                     'security_group' : None,
                                     'subnet': None,
                                     'virtual_network': data['dst_net']
                                   }],
                   'action_list': {
                       'simple_action': data['simple_action']
                                  },
                   'src_ports':src_port_list,
                   'dst_ports':dst_port_list,
                   'application':[],
                   'rule_sequence': {'major':1, 'minor':0}}
           if not policy_obj['entries']:
               policy_obj['entries'] = {}
               policy_obj['entries']['policy_rule'] = []
           if data['sequence_id'] == 'last':
               policy_obj['entries']['policy_rule'].append(rule)
           elif data['sequence_id'] == 'first':
               policy_obj['entries']['policy_rule'].insert(0, rule)
           else:
               seq = int(float(data['sequence_id'].split(':')[1]))
               policy_obj['entries']['policy_rule'].insert(seq, rule)
           policy_update_dict = policy_obj.__dict__['_apidict']['entries']
           policy = policy_modify(request, policy_id=policy_id,
                                  entries=policy_update_dict)
           messages.success(request,
                            _('Successfully added rule to policy : %s') %
                            unicode(policy['name']))
           return policy
        except:
            exceptions.handle(request, _('Unable to add rule to policy.'),
                              redirect=redirect)
