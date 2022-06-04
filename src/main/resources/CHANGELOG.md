# v1.1.43
Minor code cleanup.

# v1.1.42
Marking in the phpIPAM database of IP addresses that have not passed verification.

# v1.1.35
Added check for the absence of a PTR record on the DNS server. Added a new setting on the integration configuration screen to enable/disable validation.

# v1.1.21
Added IP address check (ping) before reservation. Added a new setting on the integration configuration screen to enable/disable validation.

# v1.1.15
Get the subnet gateway address from IPAM.

# v1.1.9
Added the ability to disable SSL certificate verification (to bypass an error when importing a chain of self-signed certificates). Added a new setting on the integration configuration screen to disable SSL certificate verification.

# v1.1.1
A new option has been added to the integration configuration screen to determine whether the vRA should receive all subnets or only those that match the filter.

# v1.1.0
Implementation of the update_record method (passing the MAC address of the VM from vRA to IPAM).

# v1.0.17
Added reservation of static IP passed from vRA.

# v1.0.12
Added authentication by token in phpIPAM API.

# v1.0.0
The first version of the plugin, basic functionality.

