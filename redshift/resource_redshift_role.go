package redshift

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lib/pq"
)

const (
	roleNameAttr         = "name"
	roleOwnerAttr        = "owner"
	roleExternalIDAttr   = "external_id"
	roleForceDestroyAttr = "force_destroy"
)

func redshiftRole() *schema.Resource {
	return &schema.Resource{
		Description: `
Defines a Redshift role. Roles are collections of permissions that can be granted to users or to other roles, and are the building block of Amazon Redshift's role-based access control (RBAC). See https://docs.aws.amazon.com/redshift/latest/dg/t_Roles.html.

Use ` + "`redshift_role_system_privileges`" + ` to grant system-level privileges to a role, and ` + "`redshift_role_grant`" + ` to assign a role to a user or to another role.
`,
		Create: RedshiftResourceFunc(resourceRedshiftRoleCreate),
		Read:   RedshiftResourceFunc(resourceRedshiftRoleRead),
		Update: RedshiftResourceFunc(resourceRedshiftRoleUpdate),
		Delete: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftRoleDelete),
		),
		Exists: RedshiftResourceExistsFunc(resourceRedshiftRoleExists),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			roleNameAttr: {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the role. The role name must be unique and can't be the same as any user name.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			roleOwnerAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Name of the role owner. Defaults to the user creating the role.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			roleExternalIDAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The identifier for the role, associated with a third-party identity provider (IdP). See https://docs.aws.amazon.com/redshift/latest/mgmt/redshift-native-idp.html.",
			},
			roleForceDestroyAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to force-drop the role, automatically revoking it from any user or role it's been granted to. By default (`false`), dropping a role that's still granted to a user or another role fails.",
			},
		},
	}
}

func resourceRedshiftRoleExists(db *DBConnection, d *schema.ResourceData) (bool, error) {
	var name string
	err := db.QueryRow("SELECT role_name FROM svv_roles WHERE role_id = $1", d.Id()).Scan(&name)

	switch {
	case err == sql.ErrNoRows:
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

func resourceRedshiftRoleCreate(db *DBConnection, d *schema.ResourceData) error {
	tx, err := startTransaction(db.client, "")
	if err != nil {
		return err
	}
	defer deferredRollback(tx)

	roleName := d.Get(roleNameAttr).(string)
	query := fmt.Sprintf("CREATE ROLE %s", pq.QuoteIdentifier(roleName))
	if externalID, ok := d.GetOk(roleExternalIDAttr); ok {
		query = fmt.Sprintf("%s EXTERNALID %s", query, pq.QuoteIdentifier(externalID.(string)))
	}

	if _, err := tx.Exec(query); err != nil {
		return fmt.Errorf("error creating role %s: %w", roleName, err)
	}

	var roleID string
	if err := tx.QueryRow("SELECT role_id FROM svv_roles WHERE role_name = $1", strings.ToLower(roleName)).Scan(&roleID); err != nil {
		return fmt.Errorf("role does not exist in svv_roles table: %w", err)
	}
	d.SetId(roleID)

	if owner, ok := d.GetOk(roleOwnerAttr); ok {
		query = fmt.Sprintf("ALTER ROLE %s OWNER TO %s", pq.QuoteIdentifier(roleName), pq.QuoteIdentifier(owner.(string)))
		if _, err := tx.Exec(query); err != nil {
			return fmt.Errorf("error setting owner for role %s: %w", roleName, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	return resourceRedshiftRoleReadImpl(db, d)
}

func resourceRedshiftRoleRead(db *DBConnection, d *schema.ResourceData) error {
	return resourceRedshiftRoleReadImpl(db, d)
}

func resourceRedshiftRoleReadImpl(db *DBConnection, d *schema.ResourceData) error {
	var roleName, roleOwner, externalID string

	query := "SELECT role_name, role_owner, COALESCE(external_id, '') FROM svv_roles WHERE role_id = $1"
	err := db.QueryRow(query, d.Id()).Scan(&roleName, &roleOwner, &externalID)
	switch {
	case err == sql.ErrNoRows:
		d.SetId("")
		return nil
	case err != nil:
		return fmt.Errorf("error reading role: %w", err)
	}

	d.Set(roleNameAttr, roleName)
	d.Set(roleOwnerAttr, roleOwner)
	d.Set(roleExternalIDAttr, externalID)

	return nil
}

func resourceRedshiftRoleUpdate(db *DBConnection, d *schema.ResourceData) error {
	tx, err := startTransaction(db.client, "")
	if err != nil {
		return err
	}
	defer deferredRollback(tx)

	if err := setRoleName(tx, d); err != nil {
		return err
	}

	if err := setRoleOwner(tx, d); err != nil {
		return err
	}

	if err := setRoleExternalID(tx, d); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	return resourceRedshiftRoleReadImpl(db, d)
}

func setRoleName(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleNameAttr) {
		return nil
	}

	oldRaw, newRaw := d.GetChange(roleNameAttr)
	oldValue := oldRaw.(string)
	newValue := newRaw.(string)

	if newValue == "" {
		return fmt.Errorf("Error setting role name to an empty string")
	}

	query := fmt.Sprintf("ALTER ROLE %s RENAME TO %s", pq.QuoteIdentifier(oldValue), pq.QuoteIdentifier(newValue))
	if _, err := tx.Exec(query); err != nil {
		return fmt.Errorf("Error updating role NAME: %w", err)
	}

	return nil
}

func setRoleOwner(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleOwnerAttr) {
		return nil
	}

	roleName := d.Get(roleNameAttr).(string)
	roleOwner := d.Get(roleOwnerAttr).(string)

	query := fmt.Sprintf("ALTER ROLE %s OWNER TO %s", pq.QuoteIdentifier(roleName), pq.QuoteIdentifier(roleOwner))
	if _, err := tx.Exec(query); err != nil {
		return fmt.Errorf("Error updating role OWNER: %w", err)
	}

	return nil
}

func setRoleExternalID(tx *sql.Tx, d *schema.ResourceData) error {
	if !d.HasChange(roleExternalIDAttr) {
		return nil
	}

	externalID := d.Get(roleExternalIDAttr).(string)
	if externalID == "" {
		return nil
	}

	roleName := d.Get(roleNameAttr).(string)
	query := fmt.Sprintf("ALTER ROLE %s EXTERNALID TO %s", pq.QuoteIdentifier(roleName), pq.QuoteIdentifier(externalID))
	if _, err := tx.Exec(query); err != nil {
		return fmt.Errorf("Error updating role EXTERNALID: %w", err)
	}

	return nil
}

func resourceRedshiftRoleDelete(db *DBConnection, d *schema.ResourceData) error {
	roleName := d.Get(roleNameAttr).(string)

	tx, err := startTransaction(db.client, "")
	if err != nil {
		return err
	}
	defer deferredRollback(tx)

	dropModifier := ""
	if d.Get(roleForceDestroyAttr).(bool) {
		dropModifier = " FORCE"
	}

	query := fmt.Sprintf("DROP ROLE %s%s", pq.QuoteIdentifier(roleName), dropModifier)
	if _, err := tx.Exec(query); err != nil {
		return err
	}

	return tx.Commit()
}
