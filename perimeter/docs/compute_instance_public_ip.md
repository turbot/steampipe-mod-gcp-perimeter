# Compute Instance Public IP

This control identifies Compute Engine instances that have been assigned public IP addresses.

## Overview

Public IP addresses on Compute Engine instances should be limited to those that explicitly require internet accessibility. Instances with public IPs are directly accessible from the internet and may be targets for attacks.

## Remediation

1. Remove public IP from instances that don't need it:
   ```bash
   gcloud compute instances delete-access-config INSTANCE_NAME \
     --access-config-name "external-nat" \
     --zone ZONE
   ```

2. For instances that need internet access, consider:
   - Using Cloud NAT for outbound internet access
   - Implementing a bastion host architecture
   - Using Internal Load Balancers
   - Using Private Google Access for API access

3. If public access is required:
   - Use firewall rules to restrict access
   - Enable Identity-Aware Proxy (IAP)
   - Implement strong authentication methods
   - Monitor access logs

## Additional Information

- [Compute Engine Networking Documentation](https://cloud.google.com/compute/docs/networking)
- [Best Practices for Enterprise Organizations](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#networking-security)
- [Using Cloud NAT](https://cloud.google.com/nat/docs/overview) 