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

"""
Views for Networking.
"""
import logging

from django.utils.translation import ugettext_lazy as _
from django.core.urlresolvers import reverse_lazy

from openstack_dashboard.api.neutron import *
from contrail_openstack_dashboard.openstack_dashboard.api.contrail_quantum import *
from horizon import exceptions
from horizon import tables
from horizon import tabs
from horizon import forms
from tables import *
from test_data import *
from forms import *
import pdb

LOG = logging.getLogger(__name__)

class NetworksTab(tabs.TableTab):
    table_classes = (NetworksTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("Networks")
    slug          = "networks_tab_table"

    def get_networks_data(self):
        try:
            tenant_id = self.request.user.tenant_id
            networks  = network_summary_for_tenant(self.request,
                                                   tenant_id)
        except:
            networks = []
            exceptions.handle(self.request,
                              _('Unable to retrieve network summary.'))
        for n in networks:
            n.set_id_as_name_if_empty()
        return networks

class PolicyTab(tabs.TableTab):
    table_classes = (PolicyTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("Network Policy")
    slug          = "policy_tab_table"

    def get_policy_data(self):
        tenant_id = self.request.user.tenant_id
        try:
            policy = policy_summary_for_tenant(self.request,
                                               tenant_id)
        except:
            policy = []
            exceptions.handle(self.request,
                              _('Unable to retrieve network policy list.'))
        return policy

class IPAMTab(tabs.TableTab):
    table_classes = (IpamTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("IPAM")
    slug          = "ipam_tab_table"

    def get_ipam_data(self):
        tenant_id = self.request.user.tenant_id
        try:
            ipam  = ipam_summary_for_tenant(self.request, tenant_id)
        except:
            ipam = []
            exceptions.handle(self.request,
                              _('Unable to retrieve ipam list.'))
        return ipam

class NetworkingTabGroup(tabs.TabGroup):
    slug = "tab_group"
    tabs = [NetworksTab, PolicyTab, IPAMTab,]


class IndexView(tabs.TabbedTableView):
    tab_group_class = NetworkingTabGroup
    template_name   = 'project/networking/index.html'

    def has_more_data(self, table):
        return getattr(self, "_more_%s" % table.name, False)

#Begin Network Detail view, move to networks/views.py

class NetPoliciesTab(tabs.TableTab):
    table_classes = (NetPolicyTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("Attached Network Policy")
    slug          = "net_assoc_pol_tab_table"

    def get_net_pol_data(self):
        net_id = self.tab_group.kwargs['id']
        try:
            net     = network_summary_get(self.request, net_id)
            pol     = net['contrail:policys']
            net_pol = []
            for p in pol:
                p_ent = {'id': p[2],
                         'name': p[2]}
                net_pol.append(p_ent)

        except:
            net_pol = []
            exceptions.handle(self.request,
                              _('Unable to retrieve associated policies.'))
        return net_pol


class NetInstancesTab(tabs.TableTab):
    table_classes = (NetInstancesTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("Ports")
    slug          = "network_instances_tab_table"

 
    def get_net_instances_data(self):
        net_id = self.tab_group.kwargs['id']
        try:
            net_instances = net_instances_summary(self.request,
                                                  network_id=net_id)
        except:
            net_instances  = []
            exceptions.handle(self.request,
                              _('Unable to retrieve associated instances.'))
        return net_instances


class IPBlocksTab(tabs.TableTab):
    table_classes = (NetIpBlockTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("IP Blocks & IPAM")
    slug          = "net_ip_block_tab_table"


    def get_net_ip_block_data(self):
        net_id = self.tab_group.kwargs['id']
        try:
            net_ip_blocks = ip_block_summary(self.request,
                                             network_id=net_id)
        except:
            net_ip_blocks = []
            exceptions.handle(self.request,
                              _('Unable to retrieve associated ip blocks.'))
        return net_ip_blocks


class NetworkDetailTabGroup(tabs.TabGroup):
    slug = "detail_tab_group"
    tabs = [IPBlocksTab, NetInstancesTab, NetPoliciesTab,]


class NetworkDetailView(tabs.TabbedTableView):
    tab_group_class = NetworkDetailTabGroup
    template_name   = 'project/networking/network_detail_tab.html'

    def get_failure_url(self):
        return get_networks_tab_group_url("networks")
    
    def _get_data(self):
        if not hasattr(self, "_network"):
            try:
                network_id = self.kwargs['id']
                network = network_summary_get(self.request, network_id)
                network.set_id_as_name_if_empty(length=0)
            except:
                msg = _('Unable to retrieve details for network "%s".') \
                      % (network_id)
                exceptions.handle(self.request, msg, redirect=self.failure_url)
            self._network = network
        return self._network

    def get_context_data(self, **kwargs):
        context = super(NetworkDetailView, self).get_context_data(**kwargs)
        context["network"] = self._get_data()
        return context

#End Network Detail View

#Begin IPAM Detail view, move to ipam/views.py

class IPAMDetailTab(tabs.TableTab):
    table_classes = (IpamDetailTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("IPAM Details")
    slug          = "ipam_detail_tab_table"

    def get_ipam_detail_data(self):
        tenant_id = self.request.user.tenant_id
        ipam_id   = self.tab_group.kwargs['id']
        ipam_options = []
        try:
            ipam  = ipam_show(self.request, ipam_id)
            self.object  = ipam
            if not ipam['mgmt'] or not ipam['mgmt']['dhcp_option_list']:
                return ipam_options
            ipam_ent     = ipam['mgmt']['dhcp_option_list']['dhcp_option']
            for i in ipam_ent:
                i_ent = {'id': "{0}:-{1}:-{2}".format(ipam_id,
                                               i['dhcp_option_name'],
                                               i['dhcp_option_value']),
                         'dhcp_option_name': i['dhcp_option_name'],
                         'dhcp_option_value': i['dhcp_option_value']}
                ipam_options.append(i_ent)
        except:
            self.object  = None
            ipam_options = []
            exceptions.handle(self.request,
                              _('Unable to retrieve ip options.'))
        return ipam_options

class IPAMDetailNetAssocTab(tabs.TableTab):
    table_classes = (IpamDetailNetAssocTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("Associated IP Blocks")
    slug          = "ipam_detail_net_assoc_tab_table"

    def get_ipam_detail_net_assoc_data(self):
        try:
            nets = []
            #Add ipam_show provides back references
        except:
            nets = []
            exceptions.handle(self.request,
                              _('Unable to retrieve ipam references.'))
        return nets


class IPAMDetailTabGroup(tabs.TabGroup):
    slug = "detail_tab_group"
    tabs = [IPAMDetailTab,]


class IpamDetailView(tabs.TabbedTableView):
    tab_group_class = IPAMDetailTabGroup
    template_name = 'project/networking/ipam_details.html'

    def get_failure_url(self):
        return get_networks_tab_group_url("ipam")

    def _get_data(self):
        if not hasattr(self, "_ipam"):
            try:
                ipam_id = self.kwargs['id']
                ipam  = ipam_show(self.request, ipam_id)
                ipam.set_id_as_name_if_empty(length=0)
            except:
                msg = _('Unable to retrieve details for network "%s".') \
                      % (ipam_id)
                exceptions.handle(self.request, msg, redirect=self.failure_url)
            self._ipam = ipam
        return self._ipam

    def get_context_data(self, **kwargs):
        context = super(IpamDetailView, self).get_context_data(**kwargs)
        context["ipam"] = self._get_data()
        return context

#Edit IPAM Options
class EditIpamView(tables.DataTableView, forms.ModalFormView):
    table_class = IpamEntryTable
    form_class  = AddIpamEntry
    template_name = 'project/networking/edit_ipam_entries.html'

    def get_success_url(self):
        return get_networks_tab_group_url("ipam")

    def get_data(self):
        tenant_id = self.request.user.tenant_id
        ipam_id   = self.kwargs['ipam_id']
        try:
            ipam  = ipam_show(self.request, ipam_id)
            self.object  = ipam
            ipam_ent     = []
            if ipam['mgmt'] and ipam['mgmt']['dhcp_option_list']: 
                ipam_ent = ipam['mgmt']['dhcp_option_list']['dhcp_option']
            ipam_entries = []
            for i in ipam_ent:
                i_ent = {'id': "{0}:-{1}:-{2}".format(ipam_id,
                                               i['dhcp_option_name'],
                                               i['dhcp_option_value']),
                         'dhcp_option_name': i['dhcp_option_name'],
                         'dhcp_option_value': i['dhcp_option_value']}
                ipam_entries.append(i_ent)
        except:
            self.object  = None
            ipam_entries = []
            exceptions.handle(self.request,
                              _('Unable to retrieve ipam entries.'))
        return ipam_entries

    def get_initial(self):
        return {'ipam_id': self.kwargs['ipam_id']}

    def get_form_kwargs(self):
        kwargs = super(EditIpamView, self).get_form_kwargs()
        return kwargs

    def get_form(self):
        if not hasattr(self, "_form"):
            form_class = self.get_form_class()
            self._form = super(EditIpamView, self).get_form(form_class)
        return self._form

    def get_context_data(self, **kwargs):
        context = super(EditIpamView, self).get_context_data(**kwargs)
        context['form'] = self.get_form()
        if self.request.is_ajax():
            context['hide'] = True
        return context

    def get(self, request, *args, **kwargs):
        # Table action handling
        handled = self.construct_tables()
        if handled:
            return handled
        if not self.object:  # Set during table construction.
            return shortcuts.redirect(self.success_url)
        context = self.get_context_data(**kwargs)
        context['ipam'] = self.object
        return self.render_to_response(context)

    def post(self, request, *args, **kwargs):
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.get(request, *args, **kwargs)
#End Edit IPAM Options

#Begin Create IPAM
class CreateIpamView(forms.ModalFormView):
    form_class = CreateIpam
    template_name = 'project/networking/create_ipam.html'

    def get_success_url(self):
        return get_networks_tab_group_url("ipam")

#End Create IPAM

#End Edit IPAM

#Begin Create Network
class CreateNetworkView(forms.ModalFormView):
    form_class = CreateNetwork
    template_name = 'project/networking/create_network.html'

    def get_success_url(self):
        return get_networks_tab_group_url("networks")

#End Create

#Begin Modify Association
class ModifyNetAssocView(forms.ModalFormView):
    form_class = ModifyNetAssoc
    template_name = 'project/networking/modify_net_assoc.html'
    context_object_name = 'network'

    def get_success_url(self):
        return get_networks_tab_group_url("networks")


    def get_context_data(self, **kwargs):
        context = super(ModifyNetAssocView, self).get_context_data(**kwargs)
        context["net_id"] = self.kwargs['net_id']
        return context


    def _get_object(self, *args, **kwargs):
        if not hasattr(self, "_object"):
            net_id = self.kwargs['net_id']
            try:
                network = network_summary_get(self.request, net_id)
                self._object = network
            except:
                redirect = self.success_url
                msg = _('Unable to retrieve network details.')
                exceptions.handle(self.request, msg, redirect=redirect)
        return self._object


    def get_initial(self):
        network = self._get_object()
        return {'net_id': network.id,
                'name': network.name,
                'net_pol': network.net_policies}


    def set_initial(self):
        network = self._get_object()
        return {'net_id': network.id,
                'name': network.name,
                'net_pol': network.net_policies}

#End Modify Association

#Begin Edit IP Blocks
class EditIPBlockView(tables.DataTableView, forms.ModalFormView):
    table_class = IPBlockTable
    form_class  = AddIPBlocks
    template_name = 'project/networking/edit_ip_block.html'

    def get_success_url(self):
        return get_networks_tab_group_url("networks")

    def get_data(self):
        net_id = self.kwargs['id']
        try:
            self.object = network_summary_get(self.request, net_id)
            ip_blocks   = ip_block_summary(self.request,
                                           network_id=net_id)
        except:
            self.object  = None
            ip_blocks = []
            exceptions.handle(self.request,
                              _('Unable to retrieve IP Blocks.'))
        return ip_blocks

    def get_initial(self):
        return {'id': self.kwargs['id']}

    def get_form_kwargs(self):
        kwargs = super(EditIPBlockView, self).get_form_kwargs()

        tenant_id = self.request.user.tenant_id
        try:
            ipams = ipam_summary_for_tenant(self.request, tenant_id)
        except:
            ipams = []
            exceptions.handle(self.request,
                              _("Unable to retrieve ipam."))
        kwargs['ipams'] = ipams
        return kwargs

    def get_form(self):
        if not hasattr(self, "_form"):
            form_class = self.get_form_class()
            self._form = super(EditIPBlockView, self).get_form(form_class)
        return self._form

    def get_context_data(self, **kwargs):
        context = super(EditIPBlockView, self).get_context_data(**kwargs)
        context['form'] = self.get_form()
        if self.request.is_ajax():
            context['hide'] = True
        return context

    def get(self, request, *args, **kwargs):
        # Table action handling
        handled = self.construct_tables()
        if handled:
            return handled
        if not self.object:  # Set during table construction.
            return shortcuts.redirect(self.success_url)
        context = self.get_context_data(**kwargs)
        context['net'] = self.object
        return self.render_to_response(context)

    def post(self, request, *args, **kwargs):
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.get(request, *args, **kwargs)

#End Edit IP Block

#Begin Create Network Policy
class CreatePolicyView(forms.ModalFormView):
    form_class = CreatePolicy
    template_name = 'project/networking/create_policy.html'

    def get_success_url(self):
        return get_networks_tab_group_url("policy")

#End Create

#Begin Policy Rule Edit
class EditPolicyRuleView(tables.DataTableView, forms.ModalFormView):
    table_class = PolicyRulesEditTable
    form_class  = AddPolicyRules
    template_name = 'project/networking/edit_policy_rules.html'

    def get_success_url(self):
        return get_networks_tab_group_url("policy")

    def get_data(self):
        tenant_id = self.request.user.tenant_id
        policy_id = self.kwargs['id']
        rules     = []
        try:
            policy  = policy_show(self.request, policy_id)
            self.object   = policy
            if policy['entries']:
                rules = policy['entries']['policy_rule']
                for r in rules:
                    r['policy_id'] = policy_id
        except:
            self.object  = None
            exceptions.handle(self.request,
                              _('Unable to retrieve policy rules.'))
        return rules

    def get_initial(self):
        return {'id': self.kwargs['id']}

    def get_form_kwargs(self):
        kwargs = super(EditPolicyRuleView, self).get_form_kwargs()
        return kwargs

    def get_form(self):
        if not hasattr(self, "_form"):
            form_class = self.get_form_class()
            self._form = super(EditPolicyRuleView, self).get_form(form_class)
        return self._form

    def get_context_data(self, **kwargs):
        context = super(EditPolicyRuleView, self).get_context_data(**kwargs)
        context['form'] = self.get_form()
        if self.request.is_ajax():
            context['hide'] = True
        return context

    def get(self, request, *args, **kwargs):
        # Table action handling
        handled = self.construct_tables()
        if handled:
            return handled
        if not self.object:  # Set during table construction.
            return shortcuts.redirect(self.success_url)
        context = self.get_context_data(**kwargs)
        context['policy'] = self.object
        return self.render_to_response(context)

    def post(self, request, *args, **kwargs):
        form = self.get_form()
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.get(request, *args, **kwargs)


#End Policy Rule Edit

#Begin Policy Detail view, move to policy/views.py

class PolicyDetailTab(tabs.TableTab):
    table_classes = (PolicyDetailTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("Policy Rules Summary")
    slug          = "policy_detail_tab_table"

    def get_policy_detail_data(self):
        tenant_id = self.request.user.tenant_id
        policy_id = self.tab_group.kwargs['id']
        try:
            policy  = policy_show(self.request, policy_id)
            self.object  = policy
            if policy['entries']:
                rules = policy['entries']['policy_rule']
            else:
                rules = []
        except:
            self.object  = None
            rules = []
            exceptions.handle(self.request,
                              _('Unable to retrieve policy rules.'))
        return rules

class PolicyDetailNetAssocTab(tabs.TableTab):
    table_classes = (PolicyDetailNetAssocTable,)
    template_name = "horizon/common/_detail_table.html"
    name          = _("Associated Networks")
    slug          = "policy_detail_net_assoc_tab_table"

    def get_policy_detail_net_assoc_data(self):
        nets = []
        tenant_id = self.request.user.tenant_id
        policy_id = self.tab_group.kwargs['id']
        try:
            policy  = policy_show(self.request, policy_id)
            self.object  = policy
            if policy['nets_using']:
                nets = policy['nets_using']
        except:
            exceptions.handle(self.request,
                              _('Unable to retrieve policy references.'))
        return nets


class PolicyDetailTabGroup(tabs.TabGroup):
    slug = "detail_tab_group"
    tabs = [PolicyDetailTab, PolicyDetailNetAssocTab,]


class PolicyDetailView(tabs.TabbedTableView):
    tab_group_class = PolicyDetailTabGroup
    template_name   = 'project/networking/policy_detail_tab.html'

    def get_failure_url(self):
        return get_networks_tab_group_url("policy")

    def _get_data(self):
        if not hasattr(self, "_policy"):
            try:
                policy_id = self.kwargs['id']
                policy  = policy_show(self.request, policy_id)
                policy.set_id_as_name_if_empty(length=0)
            except:
                msg = _('Unable to retrieve details for network "%s".') \
                      % (policy_id)
                exceptions.handle(self.request, msg, redirect=self.failure_url)
            self._policy = policy
        return self._policy

    def get_context_data(self, **kwargs):
        context = super(PolicyDetailView, self).get_context_data(**kwargs)
        context["policy"] = self._get_data()
        return context

#End Policy Detail view
