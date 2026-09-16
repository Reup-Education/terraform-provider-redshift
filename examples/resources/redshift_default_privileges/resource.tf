resource "redshift_default_privileges" "group" {
  group       = "analysts"
  owner       = "root"
  object_type = "table"
  privileges  = ["select"]
}

resource "redshift_default_privileges" "user" {
  user        = "john"
  owner       = "root"
  object_type = "table"
  privileges  = ["select", "update", "insert", "delete", "drop", "references"]
}

# Every table redshift_role.data_engineer's owner creates in my_schema from
# now on automatically grants select/insert to the role, with no need to
# re-run redshift_grant for each new table
resource "redshift_default_privileges" "role" {
  role        = redshift_role.data_engineer.name
  owner       = "root"
  schema      = "my_schema"
  object_type = "table"
  privileges  = ["select", "insert"]
}
