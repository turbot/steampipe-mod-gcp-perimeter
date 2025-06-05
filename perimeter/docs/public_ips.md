## Public IPs

The public IPs benchmark evaluates GCP resources that have been assigned public IP addresses, which could potentially expose them to direct internet access. This includes:

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

### Controls
The benchmark includes the following controls:

- **Compute Instance No Public IP**: Ensures Compute Engine instances do not have public IP addresses unless required
- **SQL Instance No Public IP**: Validates that Cloud SQL instances use private IP addresses
- **GKE Cluster No Public Endpoint**: Checks that GKE clusters use private endpoints

### Best Practices
- Use Cloud NAT for outbound internet access instead of public IPs
- Implement bastion hosts or Identity-Aware Proxy for administrative access
- Use Private Service Connect or VPC Service Controls for Google Cloud service access
- Configure internal load balancers for internal service access 