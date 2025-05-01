# Storage Bucket Public Access

This control checks for Cloud Storage buckets that have been configured to allow public access through IAM policies.

## Overview

Public access to Cloud Storage buckets should be carefully controlled to prevent unauthorized access to sensitive data. This control identifies buckets that grant access to either `allUsers` or `allAuthenticatedUsers`.

## Remediation

1. Remove public access from the bucket using one of these methods:

   Using `gsutil`:
   ```bash
   gsutil iam ch -d allUsers gs://BUCKET_NAME
   gsutil iam ch -d allAuthenticatedUsers gs://BUCKET_NAME
   ```

   Using Cloud Console:
   1. Go to Cloud Storage in the Cloud Console
   2. Select the bucket
   3. Click on "Permissions"
   4. Remove any entries for "allUsers" or "allAuthenticatedUsers"

2. Instead of public access, consider using:
   - Signed URLs for temporary access
   - Cloud IAP for authenticated access
   - Service accounts with minimal permissions
   - IAM conditions for fine-grained control

## Additional Information

- [Cloud Storage IAM Documentation](https://cloud.google.com/storage/docs/access-control/iam)
- [Best Practices for Cloud Storage Security](https://cloud.google.com/storage/docs/best-practices#security) 