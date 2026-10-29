# Import with the ID <user|role|public>:<name>/<scope>/<database>[/<schema>]
# Put the ID in quotes if it contains a space, as with the "copy jobs" scope.
# Names that contain "/" can't be imported.

terraform import redshift_scoped_grant.analyst_tables role:analyst/tables/dev/sales
terraform import redshift_scoped_grant.loader_tables user:loader/tables/dev
terraform import redshift_scoped_grant.public_languages public:public/languages/dev
terraform import redshift_scoped_grant.loader_copy_jobs "user:loader/copy jobs/dev"
