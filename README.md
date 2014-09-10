## contrail-horizon
---

## Contrail Horizon plugin
---
This software is licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

### Overview
---
Contrail extensions to Openstack Dashboard (Horizon).

Adds support for Network IPAM, Network Policy to base Openstack Dashboard.

Requires contrail neutronclient.

Add following to Openstack Dashboard settings i.e. /etc/openstack-dashboard/local_settings.py

    HORIZON_CONFIG['customization_module'] = 'contrail_openstack_dashboard.overrides'

### Contributing code
---
* Sign the [CLA](https://secure.echosign.com/public/hostedForm?formid=6G36BHPX974EXY)
* Push your changes to a topic branch in your fork of the repository.
* Submit a pull request to the contrail repository.
