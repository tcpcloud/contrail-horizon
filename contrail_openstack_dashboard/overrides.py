from django.utils.translation import ugettext_lazy as _

import horizon

from contrail_openstack_dashboard.openstack_dashboard.dashboards.projects.networking.panel import Networking
from contrail_openstack_dashboard.openstack_dashboard.dashboards.projects.networking_topology.panel import NetworkingTopology

class NetworkingPanel(horizon.Panel):
    name = "Networking"
    slug = "networking"
    urls = 'contrail_openstack_dashboard.openstack_dashboard.dashboards.projects.networking.urls'


class NetworkingTopology(horizon.Panel):
    name = _("Networking Topology")
    slug = 'networking_topology'
    urls = 'contrail_openstack_dashboard.openstack_dashboard.dashboards.projects.networking_topology.urls'


try:
    projects_dashboard = horizon.get_dashboard("project")
    try:
        topology_panel = projects_dashboard.get_panel("network_topology")
        projects_dashboard.unregister(topology_panel.__class__)
    except:
        pass
    try:
        network_panel = projects_dashboard.get_panel("networks")
        projects_dashboard.unregister(network_panel.__class__)
    except:
        pass
    try:
        routers_panel = projects_dashboard.get_panel("routers")
        projects_dashboard.unregister(routers_panel.__class__)
    except:
        pass
    try:
        lb_panel = projects_dashboard.get_panel("loadbalancers")
        projects_dashboard.unregister(lb_panel.__class__)
    except:
        pass

except:
    pass

try:
    admin_dashboard = horizon.get_dashboard("admin")
    try:
        admin_net_panel = admin_dashboard.get_panel("networks")
        admin_dashboard.unregister(admin_net_panel.__class__)
    except:
        pass
    try:
        admin_router_panel = admin_dashboard.get_panel("routers")
        admin_dashboard.unregister(admin_router_panel.__class__)
    except:
        pass
except:
    pass
