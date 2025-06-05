## Resource Policy Public Access

The resource policy public access benchmark evaluates GCP resources for potential public exposure through their IAM policies. This includes checking for policies that grant access to:
- `allUsers` - Anyone on the internet, no authentication required
- `allAuthenticatedUsers` - Any authenticated Google account, including personal Gmail users

### Resource Types Evaluated

The benchmark checks IAM policies on the following resource types:
- Cloud Storage buckets
- Pub/Sub topics
- Cloud KMS keys
- Cloud Functions
- Cloud Run services

### Risk Assessment

Public access through IAM policies can pose several risks:
- Unauthorized access to sensitive data
- Data exfiltration
- Resource abuse
- Cost implications from unauthorized usage
- Compliance violations

### Best Practices

To minimize risks from IAM policy-based public access:
- Never grant `allUsers` or `allAuthenticatedUsers` access to sensitive resources
- Use specific service accounts or Google Workspace identities instead of public access
- Implement the principle of least privilege in IAM policies
- Regularly audit and review IAM policies for public access
- Use Identity-Aware Proxy (IAP) for controlled external access
- Consider using VPC Service Controls to restrict access
- Implement organization-level constraints to prevent public IAM policies

### Additional Information

For more detailed information about specific areas, see:
- [GCP IAM Best Practices](https://cloud.google.com/iam/docs/best-practices-for-using-and-managing-service-accounts)
- [VPC Service Controls](https://cloud.google.com/vpc-service-controls/docs/overview)
- [Identity-Aware Proxy](https://cloud.google.com/iap/docs/concepts-overview) 