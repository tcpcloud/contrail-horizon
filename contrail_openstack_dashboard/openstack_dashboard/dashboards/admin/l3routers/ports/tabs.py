# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012,  Nachi Ueno,  NTT MCL,  Inc.
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

from horizon import tabs
from contrail_openstack_dashboard.openstack_dashboard.dashboards.project.l3routers.ports \
    import tabs as r_tabs


class OverviewTab(r_tabs.OverviewTab):
    template_name = "admin/networking/ports/_detail_overview.html"
    failure_url = "horizon:admin:l3routers:index"


class PortDetailTabs(tabs.TabGroup):
    slug = "port_details"
    tabs = (OverviewTab,)
