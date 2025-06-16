## Firewall Access

This benchmark answers the following questions:

- Are there any firewall rules allowing unrestricted TCP/UDP access from 0.0.0.0/0?
- Are there any firewall rules allowing access to sensitive ports (SSH, RDP, MySQL, PostgreSQL, MongoDB, MSSQL, etc.) from 0.0.0.0/0 or ::/0?
- Are there any firewall rules allowing access from IPv6 addresses (::/0)?

### Included Controls

- **VPC Firewall Restrict Ingress TCP/UDP**: Checks if any firewall rules allow inbound TCP or UDP access from 0.0.0.0/0
- **VPC Firewall Restrict Ingress Common Ports**: Verifies if any firewall rules allow access to common sensitive ports (SSH, RDP, databases, etc.) from 0.0.0.0/0 or ::/0

### Best Practices
- Use service accounts and IAM for service-to-service communication where possible
- Implement the principle of least privilege in firewall rules
- Regularly audit and remove unnecessary firewall rules
- Use tags and service accounts instead of IP ranges where appropriate 