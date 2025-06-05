benchmark "public_access" {
  title         = "Public Access"
  description   = "Resources should not be exposed to the internet or publicly accessible."
  documentation = file("./perimeter/docs/public_access.md")
  children = [
    benchmark.public_access_compute,
    benchmark.public_access_database,
    benchmark.public_access_network
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "public_access_compute" {
  title         = "Public Access Compute"
  description   = "Compute resources should not be exposed to the internet through public IP addresses or network configurations."
  documentation = file("./perimeter/docs/public_access_compute.md")
  children = [
    control.compute_instance_no_public_ip,
    control.cloud_function_vpc_connector,
    control.cloud_run_vpc_connector,
    control.gke_cluster_private_nodes,
    control.gke_cluster_no_public_endpoint
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "public_access_database" {
  title         = "Public Access Database"
  description   = "Database resources should not be exposed to the internet through public IP addresses or network configurations."
  documentation = file("./perimeter/docs/public_access_database.md")
  children = [
    control.sql_instance_no_public_ip,
    control.memorystore_instance_private_ip
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
}

benchmark "public_access_network" {
  title         = "Public Access Network"
  description   = "Network configurations should not allow unrestricted access from the internet."
  documentation = file("./perimeter/docs/public_access_network.md")
  children = [
    control.firewall_rule_restrict_ingress_all,
    control.firewall_rule_restrict_ingress_common_ports
  ]

  tags = merge(local.gcp_perimeter_common_tags, {
    type = "Benchmark"
  })
} 