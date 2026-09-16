# Assign a role to a user
resource "redshift_role_grant" "data_engineer_to_alice" {
  role = redshift_role.data_engineer.name
  user = redshift_user.alice.name
}

# Assign a role to a user, allowing that user to grant the role to others
resource "redshift_role_grant" "data_engineer_to_bob_with_admin" {
  role         = redshift_role.data_engineer.name
  user         = redshift_user.bob.name
  admin_option = true
}

# Assign a role to another role, forming a role hierarchy:
# analyst inherits every permission granted to data_engineer
resource "redshift_role_grant" "data_engineer_to_analyst" {
  role         = redshift_role.data_engineer.name
  grantee_role = redshift_role.analyst.name
}
