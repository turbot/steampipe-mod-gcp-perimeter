## Firewall Access

The firewall access benchmark evaluates GCP firewall rules for configurations that could allow unauthorized access from the internet. This includes:

### Ingress Rules
Firewall rules should carefully restrict inbound access:
- Rules should not allow unrestricted access from 0.0.0.0/0
- Common ports (e.g., SSH, RDP, database ports) should be restricted
- Access should be limited to specific IP ranges or resources

### Common Ports
The following ports are considered sensitive and should be restricted:
- SSH (22)
- RDP (3389)
- MySQL (3306)
- MSSQL (1433)
- PostgreSQL (5432)
- MongoDB (27017)

### Controls
The benchmark includes the following controls:

- **Firewall Rule Restrict Ingress All**: Checks for rules that allow unrestricted ingress from 0.0.0.0/0
- **Firewall Rule Restrict Ingress Common Ports**: Validates that common ports are not exposed to 0.0.0.0/0

### Best Practices
- Use service accounts and IAM for service-to-service communication where possible
- Implement the principle of least privilege in firewall rules
- Regularly audit and remove unnecessary firewall rules
- Use tags and service accounts instead of IP ranges where appropriate 