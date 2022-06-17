vRA 8 phpIPAM Integration plugin
============

This integration plugin allows vRealize Automation 8 to use [phpIPAM](https://phpipam.net).

A detailed description of the plugin can be found here: [vRA 8: phpIPAM plugin](https://as.zabedu.ru/en/virtual2/vmware2/vrealize2/vra-phpipam-en)

### Key features of the plugin v1.1.43
* User authentication by login/password;
* API token authentication;
* Disabling SSL certificate verification (to bypass an error when importing a chain of self-signed certificates, it is enabled in the plugin settings);
* Filtering the list of available vRA subnets (enabled in the plugin settings);
* Reservation of the first free IP address from the subnet;
* IP unavailability check (ping) before reservation (enabled in plugin settings);
* Checking the absence of a PTR record on the DNS server (enabled in the plugin settings);
* Marking in the IPAM database of IPs that have not passed the test;
* Reservation of static IP passed from vRA;
* Static IP check via ping and comparison by hostname if IP is already reserved in IPAM;
* Get subnet gateway address from IPAM;
* Implementation of the update_record method (passing the MAC address of the VM from vRA to IPAM).