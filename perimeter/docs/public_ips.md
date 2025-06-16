## Public IPs

This benchmark answers the following questions:

- Are any Cloud Functions or Cloud Run services publicly accessible?
- Are any Cloud SQL instances configured with public IP addresses?
- Are any Compute Engine instances assigned public IP addresses?
- Are any GKE clusters using public nodes or endpoints?

### Included Controls

- **Cloud Function Not Publicly Accessible**: Checks if Cloud Functions have VPC connectors and internal-only ingress settings
- **Cloud Run Not Publicly Accessible**: Verifies if Cloud Run services have VPC access and internal-only ingress
- **Cloud SQL Not Publicly Accessible**: Ensures Cloud SQL instances don't have public IP addresses
- **Compute Instance Not Publicly Accessible**: Validates that Compute Engine instances don't have public IP addresses
- **GKE Cluster Not Publicly Accessible**: Confirms that GKE clusters use private nodes and have legacy endpoints disabled

### Resource Types
The following resource types are evaluated for public IP exposure:
- Compute Engine instances
- Cloud SQL instances
- GKE cluster endpoints

### Risk Assessment
Public IP addresses can pose several risks:
- Direct internet accessibility to resources
- Increased attack surface for potential threats
- Bypass of network security controls
- Potential data exfiltration paths

### Best Practices
- Use Cloud NAT for outbound internet access instead of public IPs
- Implement bastion hosts or Identity-Aware Proxy for administrative access
- Use Private Service Connect or VPC Service Controls for Google Cloud service access
- Configure internal load balancers for internal service access 