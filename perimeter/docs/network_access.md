## Network Access

The network access benchmark evaluates GCP resources for potential exposure to the internet through various network configurations. This includes checking:

- Network general access controls for resources that should be in VPCs or use private endpoints
- Firewall rules that might allow unrestricted access from the internet
- Resources with public IP addresses that could be directly accessible from the internet

### Categories

- **Network General Access**: Evaluates resources for basic network security best practices like VPC connectivity and private access configurations.
- **Firewall Access**: Checks firewall rules for overly permissive configurations that could allow unauthorized access.
- **Public IPs**: Identifies resources that have been assigned public IP addresses which could expose them to direct internet access.

A properly configured network is essential to secure your GCP environment from being exploited by unauthorized users. Access control for network boundaries and allowlists for network communications are required and should follow recommended industry-standard best practices.

The network access benchmark checks for GCP resources which are at risk due to network misconfigurations such as overly permissive firewall rules, disabled flow logs, or disabled Private Google Access. 