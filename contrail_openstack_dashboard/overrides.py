from django.utils.translation import ugettext_lazy as _

import horizon

from contrail_openstack_dashboard.openstack_dashboard.dashboards.project.networking.panel \
    import Networking
from contrail_openstack_dashboard.openstack_dashboard.dashboards.admin.networking.panel \
    import AdminNetworking
from contrail_openstack_dashboard.openstack_dashboard.dashboards.project.networking_topology.panel \
    import NetworkingTopology
from contrail_openstack_dashboard.openstack_dashboard.dashboards.project.l3routers.panel \
    import L3Routers
from contrail_openstack_dashboard.openstack_dashboard.dashboards.admin.l3routers.panel \
    import L3AdminRouters
from contrail_openstack_dashboard.openstack_dashboard.dashboards.project.lbaas.panel \
    import LoadBalancer

class NetworkingPanel(horizon.Panel):
    name = "Networking"
    slug = "networking"
    urls = 'contrail_openstack_dashboard.openstack_dashboard.dashboards.project.networking.urls'


class AdminNetworkingPanel(horizon.Panel):
    name = "Networking"
    slug = "networking"
    urls = 'contrail_openstack_dashboard.openstack_dashboard.dashboards.admin.networking.urls'


class NetworkingTopology(horizon.Panel):
    name = _("Networking Topology")
    slug = 'networking_topology'
    urls = 'contrail_openstack_dashboard.openstack_dashboard.dashboards.project.networking_topology.urls'


class L3Routers(horizon.Panel):
    name = _("Routers")
    slug = 'l3routers'
    urls = 'contrail_openstack_dashboard.openstack_dashboard.dashboards.project.l3routers.urls'


class L3AdminRouters(horizon.Panel):
    name = _("Routers")
    slug = 'l3routers'
    urls = 'contrail_openstack_dashboard.openstack_dashboard.dashboards.admin.l3routers.urls'


class LoadBalancer(horizon.Panel):
    name = _("Load Balancers")
    slug = 'lbaas'
    urls = 'contrail_openstack_dashboard.openstack_dashboard.dashboards.admin.lbaas.urls'


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
