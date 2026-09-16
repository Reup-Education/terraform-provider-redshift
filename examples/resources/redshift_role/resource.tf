# Example resource declaration of a role
resource "redshift_role" "data_engineer" {
  name = "data_engineer"
}

# Example resource declaration of a role owned by a specific user,
# associated with a third-party identity provider
resource "redshift_role" "sso_analyst" {
  name        = "sso_analyst"
  owner       = "admin"
  external_id = "ABC123"
}
