# Public Access Benchmark

## Overview

The Public Access benchmark assesses GCP resources that might be exposed to the public internet. Public exposure of cloud resources can increase security risks and should be carefully controlled.

## Categories of Controls

### Storage Controls
- **Storage Bucket Public Access**: Checks for Cloud Storage buckets that grant public access through IAM policies.

### Compute Controls
- **Compute Instance Public IP**: Identifies Compute Engine instances that have public IP addresses assigned.

### Database Controls
- **Cloud SQL Public IP**: Detects Cloud SQL instances that are configured with public IP addresses.

## Best Practices

1. **Limit Public Storage Access**
   - Use signed URLs or Cloud IAP for temporary access
   - Implement proper IAM roles instead of public access
   - Regularly audit bucket permissions

2. **Restrict Public IP Usage**
   - Use Cloud NAT for outbound internet access
   - Implement bastion hosts for administrative access
   - Use Internal Load Balancers where possible

3. **Secure Database Access**
   - Use Private IP for database connections
   - Implement Cloud SQL Auth proxy
   - Use SSL/TLS for all database connections

## References

- [Cloud Storage Security Best Practices](https://cloud.google.com/storage/docs/best-practices)
- [Compute Engine Security Best Practices](https://cloud.google.com/compute/docs/security/best-practices)
- [Cloud SQL Security Best Practices](https://cloud.google.com/sql/docs/mysql/security-best-practices) 