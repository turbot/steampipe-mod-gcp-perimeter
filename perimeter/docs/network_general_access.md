## Network General Access

This benchmark answers the following questions:

- Are Cloud Functions and Cloud Run services configured with VPC connectors for secure internal communication?
- Are Cloud SQL instances using private IP addresses instead of public IPs?
- Are GKE clusters configured with master authorized networks and network policies?
- Are Redis instances (Memorystore) using private service access and custom networks?

### Included Controls

- **Cloud Functions Ingress Settings**: Checks if Cloud Functions are restricted to internal or internal with load balancer traffic
- **Cloud Run Service Ingress**: Verifies if Cloud Run services are restricted to internal or internal with load balancer traffic
- **SQL Database Instance Authorized Networks**: Ensures Cloud SQL instances don't allow access from 0.0.0.0/0
- **Kubernetes Cluster Master Authorized Networks**: Validates that GKE clusters have restricted access to the Kubernetes API server
- **Kubernetes Cluster Network Policy**: Confirms that GKE clusters have network policy enabled for pod-to-pod communication
- **Redis Instance Authorized Network**: Checks if Memorystore Redis instances use private service access and custom networks 