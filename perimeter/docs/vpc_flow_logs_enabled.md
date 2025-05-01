# VPC Flow Logs Enabled

This control checks whether VPC flow logs are enabled for your VPC networks.

## Overview

VPC Flow Logs record information about network traffic in your VPC networks. This information is crucial for network monitoring, forensics, and security analysis.

## Remediation

1. Enable flow logs for a subnet:
   ```bash
   gcloud compute networks subnets update SUBNET_NAME \
     --region=REGION \
     --enable-flow-logs
   ```

2. Enable flow logs for all subnets in a VPC:
   ```bash
   gcloud compute networks update NETWORK_NAME \
     --bgp-routing-mode=ROUTING_MODE \
     --subnet-mode=auto \
     --enable-subnet-flow-logs
   ```

3. Best practices for flow logs:
   - Set appropriate sampling rates
   - Configure log exports to security tools
   - Set retention policies
   - Monitor for suspicious patterns
   - Use aggregated logs for analysis

## Additional Information

- [VPC Flow Logs Overview](https://cloud.google.com/vpc/docs/flow-logs)
- [Using VPC Flow Logs](https://cloud.google.com/vpc/docs/using-flow-logs)
- [Flow Logs Best Practices](https://cloud.google.com/vpc/docs/flow-logs#best_practices) 