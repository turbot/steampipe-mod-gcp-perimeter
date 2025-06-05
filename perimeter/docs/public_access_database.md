## Public Access Database

The public access database benchmark evaluates GCP database resources for potential public exposure through network configurations. This includes checking:

- Cloud SQL instances with public IP addresses
- Database network configuration settings that might allow public access

### Controls

- **Cloud SQL Public IP**: Identifies Cloud SQL instances that have public IP addresses enabled. While some database instances may require public IPs for specific use cases (e.g., external application access), it's generally recommended to keep databases private and access them through private IP addresses or authorized networks only to enhance security. 