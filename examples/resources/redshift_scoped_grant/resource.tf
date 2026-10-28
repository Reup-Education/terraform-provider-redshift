# Read access to all current and future tables in one schema
resource "redshift_scoped_grant" "analyst_tables" {
  role       = redshift_role.analyst.name
  scope      = "tables"
  schema     = "sales"
  privileges = ["select"]
}

# Without a schema, the permissions apply to all schemas in the database
resource "redshift_scoped_grant" "loader_tables" {
  user       = "loader"
  scope      = "tables"
  privileges = ["select", "insert", "update", "delete"]
}

# The functions scope also applies to stored procedures
resource "redshift_scoped_grant" "analyst_functions" {
  role       = redshift_role.analyst.name
  scope      = "functions"
  schema     = "sales"
  privileges = ["execute"]
}

# Permissions in a database other than the provider database
resource "redshift_scoped_grant" "analyst_schemas" {
  role       = redshift_role.analyst.name
  scope      = "schemas"
  database   = "reporting"
  privileges = ["usage"]
}

# Grant to PUBLIC, which includes all users
resource "redshift_scoped_grant" "public_languages" {
  public     = true
  scope      = "languages"
  privileges = ["usage"]
}
