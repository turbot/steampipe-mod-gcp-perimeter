# Public IP Access

Resources should not be assigned public IP addresses unless necessary. This benchmark evaluates various GCP resources to identify those that are directly accessible from the internet through public IP addresses.

## Overview

Public IP addresses make resources directly accessible from the internet, which increases the attack surface and the risk of unauthorized access. This benchmark helps identify resources that have public IP addresses assigned to ensure they align with your security requirements.

## Categories of Controls

The benchmark includes the following categories of controls:

1. **Compute Instance Public IPs**: Checks if Compute Engine instances have public IP addresses
2. **Cloud SQL Public IPs**: Identifies Cloud SQL instances with public IP addresses enabled
3. **GKE Cluster Public IPs**: Detects GKE clusters with nodes that have public IP addresses
4. **Cloud Function Public IPs**: Monitors Cloud Functions for public IP exposure
5. **Cloud Run Public IPs**: Identifies Cloud Run services with public IP addresses

## Best Practices

- Use Cloud NAT for outbound internet access instead of public IPs
- Configure Private Service Connect for accessing Google Cloud services
- Use load balancers or Cloud IAP for public access to applications
- Implement VPC Service Controls to restrict resource access
- Document and maintain an inventory of resources that require public IPs 