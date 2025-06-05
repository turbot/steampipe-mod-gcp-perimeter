## Public Access Compute

The public access compute benchmark evaluates GCP compute resources for potential public exposure through network configurations. This includes checking:

- Compute Engine instances with public IP addresses
- Network interfaces with public access configurations

### Controls

- **Compute Instance Public IP**: Identifies compute instances that have been assigned public IP addresses, which could potentially expose them to direct internet access. While some instances may require public IPs for legitimate purposes (e.g., public-facing web servers), unnecessary public IP assignments should be avoided to reduce the attack surface. 