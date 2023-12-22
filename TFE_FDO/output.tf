output "bucket_object_path" {
  value = aws_s3_object.license.key
}

output "test" {
  value = join(",", flatten([
      for az in var.map_subnet_az[var.aws_region] : az.cidr_block
    ]))
}

output "redis_host" {
  value = aws_elasticache_replication_group.name.member_clusters
}

# output "address_why" {
#   value = aws_elasticache_replication_group.name.configuration_endpoint_address
# }

# data "aws_elasticache_cluster" "example_clusters" {
#   count = length(aws_elasticache_replication_group.name.member_clusters)

#   cluster_id = aws_elasticache_replication_group.name.member_clusters
# }

# output "member_clusters_endpoints" {
#   value = [for cluster in data.aws_elasticache_cluster.example_clusters : cluster.configuration_endpoint]
# }