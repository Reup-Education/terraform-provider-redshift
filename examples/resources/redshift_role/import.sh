# Import role with role_id: SELECT role_id FROM svv_roles WHERE role_name = 'myrole'

terraform import redshift_role.myrole 234
