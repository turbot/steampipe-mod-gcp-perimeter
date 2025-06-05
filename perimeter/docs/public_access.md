## Public Access

The public access benchmark evaluates GCP resources for potential exposure to the internet through various mechanisms. This includes checking:

### Categories

- **Public Access Settings**: Evaluates resources for configuration settings that could allow public access, such as:
  - Public IP addresses on compute instances
  - Public endpoints on managed services
  - Firewall rules allowing unrestricted access
  - VPC connectivity settings

- **Resource Policy Public Access**: Checks IAM policies for statements that grant public access through:
  - `allUsers` - Anyone on the internet, no authentication required
  - `allAuthenticatedUsers` - Any authenticated Google account, including personal Gmail users

### Resource Types Evaluated

The benchmark evaluates public access across multiple resource types:
- Compute Engine instances
- Cloud Functions
- Cloud Run services
- GKE clusters
- Cloud SQL instances
- Memorystore instances
- VPC firewall rules
- Cloud Storage buckets
- Pub/Sub topics
- Cloud KMS keys

### Risk Assessment

Public access to cloud resources can pose several risks:
- Unauthorized access to sensitive data
- Data exfiltration
- Resource abuse and cost implications
- Increased attack surface
- Bypass of security controls
- Compliance violations

### Best Practices

To minimize public exposure risks:

Configuration Best Practices:
- Use private IP addresses where possible
- Configure VPC connectors for serverless services
- Enable private endpoints for managed services
- Use Cloud NAT for outbound internet access
- Restrict firewall rules to specific IP ranges
- Use internal load balancers for internal service access

IAM Policy Best Practices:
- Never grant `allUsers` or `allAuthenticatedUsers` access to sensitive resources
- Use specific service accounts or Google Workspace identities
- Implement the principle of least privilege
- Regularly audit and review IAM policies
- Use Identity-Aware Proxy (IAP) for controlled external access

Additional Security Controls:
- Implement VPC Service Controls
- Enable Private Google Access
- Use organization-level constraints
- Configure bastion hosts for administrative access

### Additional Information

For more detailed information about specific areas, see:
- [Public Access Settings](./public_access_settings.md)
- [Resource Policy Public Access](./resource_policy_public_access.md) 