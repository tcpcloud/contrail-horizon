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

from django.conf.urls.defaults import *

from .views import *
#from .ipam import urls as ipam_urls
#from .policies import urls as policies_urls
#from .networks import urls as networks_urls
#from .connections import urls as connections_urls

urlpatterns = patterns('',
    url(r'^$', IndexView.as_view(), name='index'),
    url(r'^(?P<id>[^/]+)/network_detail/$',
        NetworkDetailView.as_view(), name='network_detail'),
    url(r'^(?P<id>[^/]+)/edit_ip_block/$',
        EditIPBlockView.as_view(), name='edit_ip_block'),
    url(r'^(?P<ipam_id>[^/]+)/edit_ipam_entries/$',
        EditIpamView.as_view(), name='edit_ipam_entries'),
    url(r'^(?P<id>[^/]+)/policy_detail/$',
        PolicyDetailView.as_view(), name='policy_detail'),
    url(r'^(?P<id>[^/]+)/ipam_detail/$',
        IpamDetailView.as_view(), name='ipam_detail'),
    url(r'^(?P<net_id>[^/]+)/modify_net_assoc/$',
        ModifyNetAssocView.as_view(), name='modify_net_assoc'),
    url(r'^create_ipam/$', CreateIpamView.as_view(), name='create_ipam'),
    url(r'^create_network/$', CreateNetworkView.as_view(),
                           name='create_network'),
    url(r'^create_policy/$', CreatePolicyView.as_view(),
                           name='create_policy'),
    url(r'^(?P<id>[^/]+)/edit_policy_rules/$',
        EditPolicyRuleView.as_view(), name='edit_policy_rules'),
#    url(r'net_ipam/', include(net_ipam_urls, namespace='ipam_urls')),
#    url(r'networks/', include(networks_urls, namespace='networks_urls')),
#    url(r'policies/', include(policies_urls, namespace='policies_urls')),
#    url(r'connections/', include(connections_urls,
#                                 namespace='connections_urls')),
)
