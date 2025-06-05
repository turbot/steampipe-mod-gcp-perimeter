## Network General Access

The network general access benchmark evaluates GCP resources for adherence to network security best practices. This includes:

### VPC Connectivity
Resources should be configured to use VPC networks and connectors where possible:
- Cloud Functions should use VPC connectors to securely communicate with other resources
- Cloud Run services should use VPC connectors for secure internal communication
- Cloud SQL instances should use private IP addresses for VPC access
- GKE clusters should use private nodes to prevent direct internet exposure
- Memorystore instances should use private IP addresses for secure access

### Private Access
Resources should prefer private access methods over public ones:
- Cloud SQL instances should be configured for private IP access
- GKE clusters should use private nodes and endpoints
- Memorystore instances should be restricted to private IP access

### Controls
The benchmark includes the following controls:

- **Cloud Function VPC Connector**: Ensures Cloud Functions are configured with VPC connectors
- **Cloud Run VPC Connector**: Verifies Cloud Run services use VPC connectors
- **Cloud SQL Instance Private IP**: Checks if Cloud SQL instances are configured for private IP access
- **GKE Cluster Private Nodes**: Validates that GKE clusters use private nodes
- **Memorystore Instance Private IP**: Ensures Memorystore instances use private IP configuration 