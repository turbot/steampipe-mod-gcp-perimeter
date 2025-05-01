# Cloud SQL Public IP

This control checks for Cloud SQL instances that are configured with public IP addresses.

## Overview

Cloud SQL instances should use private IP addresses whenever possible to prevent exposure to the public internet. Public IP addresses should only be used when required by the application architecture and should be properly secured.

## Remediation

1. Disable public IP for instances that don't need it:
   ```bash
   gcloud sql instances patch INSTANCE_NAME \
     --no-assign-ip
   ```

2. For instances requiring external access, consider:
   - Using the Cloud SQL Auth proxy
   - Implementing SSL/TLS connections
   - Using authorized networks to restrict access
   - Using Private Service Connect

3. If public IP is required:
   - Configure authorized networks to limit access
   - Enable SSL/TLS for all connections
   - Use strong authentication methods
   - Monitor access logs

## Additional Information

- [Cloud SQL Networking](https://cloud.google.com/sql/docs/mysql/configure-ip)
- [Cloud SQL Auth Proxy](https://cloud.google.com/sql/docs/mysql/sql-proxy)
- [Private IP for Cloud SQL](https://cloud.google.com/sql/docs/mysql/private-ip)
- [Cloud SQL Security Best Practices](https://cloud.google.com/sql/docs/mysql/security-best-practices) 