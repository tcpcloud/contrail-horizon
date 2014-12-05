
|License badge|

Contrail Horizon plugin
======

Contrail extensions to Openstack Dashboard (Horizon).

Adds support for Network IPAM, Network Policy to base Openstack Dashboard.


Installation
------

Requires contrail neutronclient.

Add following to Openstack Dashboard settings i.e. /etc/openstack-dashboard/local_settings.py

.. code-block:: python

    INSTALLED_APPS += ('contrail_openstack_dashboard',)
    HORIZON_CONFIG['customization_module'] = 'contrail_openstack_dashboard.overrides'


Contributing code
------

* Sign the [CLA](https://secure.echosign.com/public/hostedForm?formid=6G36BHPX974EXY)
* Push your changes to a topic branch in your fork of the repository.
* Submit a pull request to the contrail repository.

.. |License badge| image:: http://img.shields.io/badge/license-Apache%202.0-green.svg?style=flat