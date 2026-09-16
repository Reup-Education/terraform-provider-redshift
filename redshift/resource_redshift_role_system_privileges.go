package redshift

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/lib/pq"
)

const (
	roleSystemPrivilegesRoleAttr       = "role"
	roleSystemPrivilegesPrivilegesAttr = "privileges"
)

// validRoleSystemPrivileges lists the system-level privileges that can be granted to a
// role, per https://docs.aws.amazon.com/redshift/latest/dg/r_GRANT.html#grant-roles.
var validRoleSystemPrivileges = []string{
	"CREATE USER",
	"DROP USER",
	"ALTER USER",
	"CREATE SCHEMA",
	"DROP SCHEMA",
	"ALTER DEFAULT PRIVILEGES",
	"CREATE TABLE",
	"DROP TABLE",
	"ALTER TABLE",
	"CREATE OR REPLACE FUNCTION",
	"CREATE OR REPLACE EXTERNAL FUNCTION",
	"DROP FUNCTION",
	"CREATE OR REPLACE PROCEDURE",
	"DROP PROCEDURE",
	"CREATE OR REPLACE VIEW",
	"DROP VIEW",
	"CREATE MODEL",
	"DROP MODEL",
	"CREATE DATASHARE",
	"ALTER DATASHARE",
	"DROP DATASHARE",
	"CREATE LIBRARY",
	"DROP LIBRARY",
	"CREATE ROLE",
	"DROP ROLE",
	"TRUNCATE TABLE",
	"VACUUM",
	"ANALYZE",
	"CANCEL",
}

func redshiftRoleSystemPrivileges() *schema.Resource {
	return &schema.Resource{
		Description: `
Grants Amazon Redshift system-level privileges to a role, such as the ability to run commands that would otherwise require superuser permissions (for example ` + "`CREATE TABLE`" + ` or ` + "`CREATE USER`" + `). See https://docs.aws.amazon.com/redshift/latest/dg/r_GRANT.html#grant-roles.

This resource manages the full set of system privileges for a role: applying it revokes any system privileges not listed in ` + "`privileges`" + `.
`,
		Create: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftRoleSystemPrivilegesCreate),
		),
		Read: RedshiftResourceFunc(resourceRedshiftRoleSystemPrivilegesRead),
		// Since we revoke all when creating, we can use create as update
		Update: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftRoleSystemPrivilegesCreate),
		),
		Delete: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftRoleSystemPrivilegesDelete),
		),

		Schema: map[string]*schema.Schema{
			roleSystemPrivilegesRoleAttr: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the role to grant system privileges to.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			roleSystemPrivilegesPrivilegesAttr: {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.StringInSlice(validRoleSystemPrivileges, true),
					StateFunc: func(val interface{}) string {
						return strings.ToLower(val.(string))
					},
				},
				Set:         schema.HashString,
				Description: "The list of system privileges to grant to the role. See [GRANT command documentation](https://docs.aws.amazon.com/redshift/latest/dg/r_GRANT.html#grant-roles) for the full list of available system privileges. An empty list revokes all system privileges from the role.",
			},
		},
	}
}

func resourceRedshiftRoleSystemPrivilegesCreate(db *DBConnection, d *schema.ResourceData) error {
	roleName := d.Get(roleSystemPrivilegesRoleAttr).(string)

	tx, err := startTransaction(db.client, "")
	if err != nil {
		return err
	}
	defer deferredRollback(tx)

	revokeQuery := fmt.Sprintf("REVOKE ALL PRIVILEGES FROM ROLE %s", pq.QuoteIdentifier(roleName))
	if _, err := tx.Exec(revokeQuery); err != nil {
		return fmt.Errorf("error revoking existing system privileges from role %s: %w", roleName, err)
	}

	privileges := []string{}
	for _, p := range d.Get(roleSystemPrivilegesPrivilegesAttr).(*schema.Set).List() {
		privileges = append(privileges, strings.ToUpper(p.(string)))
	}

	if len(privileges) > 0 {
		grantQuery := fmt.Sprintf("GRANT %s TO ROLE %s", strings.Join(privileges, ","), pq.QuoteIdentifier(roleName))
		if _, err := tx.Exec(grantQuery); err != nil {
			return fmt.Errorf("error granting system privileges to role %s: %w", roleName, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	d.SetId(roleName)

	return resourceRedshiftRoleSystemPrivilegesReadImpl(db, d)
}

func resourceRedshiftRoleSystemPrivilegesRead(db *DBConnection, d *schema.ResourceData) error {
	return resourceRedshiftRoleSystemPrivilegesReadImpl(db, d)
}

func resourceRedshiftRoleSystemPrivilegesReadImpl(db *DBConnection, d *schema.ResourceData) error {
	roleName := d.Get(roleSystemPrivilegesRoleAttr).(string)

	rows, err := db.Query(
		"SELECT system_privilege FROM svv_system_privileges WHERE identity_type = 'role' AND identity_name = $1",
		roleName,
	)
	if err != nil {
		return fmt.Errorf("error reading system privileges for role %s: %w", roleName, err)
	}
	defer rows.Close()

	privileges := schema.NewSet(schema.HashString, nil)
	for rows.Next() {
		var privilege string
		if err := rows.Scan(&privilege); err != nil {
			return err
		}
		privileges.Add(strings.ToLower(privilege))
	}

	d.Set(roleSystemPrivilegesPrivilegesAttr, privileges)

	return nil
}

func resourceRedshiftRoleSystemPrivilegesDelete(db *DBConnection, d *schema.ResourceData) error {
	roleName := d.Get(roleSystemPrivilegesRoleAttr).(string)

	query := fmt.Sprintf("REVOKE ALL PRIVILEGES FROM ROLE %s", pq.QuoteIdentifier(roleName))
	_, err := db.Exec(query)
	return err
}
