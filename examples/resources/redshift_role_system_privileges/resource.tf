# Let the data_engineer role create and manage tables and schemas
# without needing superuser access
resource "redshift_role_system_privileges" "data_engineer" {
  role = redshift_role.data_engineer.name
  privileges = [
    "create schema",
    "drop schema",
    "create table",
    "drop table",
    "alter table",
  ]
}
