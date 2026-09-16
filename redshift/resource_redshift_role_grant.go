package redshift

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lib/pq"
)

const (
	roleGrantRoleAttr        = "role"
	roleGrantUserAttr        = "user"
	roleGrantGranteeRoleAttr = "grantee_role"
	roleGrantAdminOptionAttr = "admin_option"
)

func redshiftRoleGrant() *schema.Resource {
	return &schema.Resource{
		Description: `
Assigns a Redshift role to a user or to another role. Granting a role authorizes the grantee with all the permissions included in that role, and (when granted to another role) any role granted to it, forming a role hierarchy. See https://docs.aws.amazon.com/redshift/latest/dg/t_role_assignment.html and https://docs.aws.amazon.com/redshift/latest/dg/t_role_hierarchy.html.
`,
		Create: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftRoleGrantCreate),
		),
		Read: RedshiftResourceFunc(resourceRedshiftRoleGrantRead),
		Delete: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftRoleGrantDelete),
		),
		Exists: RedshiftResourceExistsFunc(resourceRedshiftRoleGrantExists),
		CustomizeDiff: func(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
			_, hasGranteeRole := d.GetOk(roleGrantGranteeRoleAttr)
			if hasGranteeRole && d.Get(roleGrantAdminOptionAttr).(bool) {
				return fmt.Errorf("%s can't be true when %s is set: WITH ADMIN OPTION only applies to users, not roles", roleGrantAdminOptionAttr, roleGrantGranteeRoleAttr)
			}
			return nil
		},

		Schema: map[string]*schema.Schema{
			roleGrantRoleAttr: {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The name of the role to grant.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			roleGrantUserAttr: {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ExactlyOneOf: []string{roleGrantUserAttr, roleGrantGranteeRoleAttr},
				Description:  "The name of the user to grant the role to. Either `user` or `grantee_role` must be set.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			roleGrantGranteeRoleAttr: {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ExactlyOneOf: []string{roleGrantUserAttr, roleGrantGranteeRoleAttr},
				Description:  "The name of another role to grant the role to, creating a role hierarchy. Either `grantee_role` or `user` must be set.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			roleGrantAdminOptionAttr: {
				Type:        schema.TypeBool,
				Optional:    true,
				ForceNew:    true,
				Default:     false,
				Description: "Whether the grantee user can in turn grant this role to other users and roles. Only valid when `user` is set; can't be used with `grantee_role`.",
			},
		},
	}
}

func resourceRedshiftRoleGrantExists(db *DBConnection, d *schema.ResourceData) (bool, error) {
	found, _, err := roleGrantLookup(db, d)
	return found, err
}

// roleGrantLookup checks whether the role grant described by d currently exists,
// returning its current admin_option value (only meaningful for user grantees).
func roleGrantLookup(db *DBConnection, d *schema.ResourceData) (bool, bool, error) {
	roleName := d.Get(roleGrantRoleAttr).(string)

	if userName, isUser := d.GetOk(roleGrantUserAttr); isUser {
		var adminOption bool
		query := "SELECT admin_option FROM svv_user_grants WHERE role_name = $1 AND user_name = $2"
		err := db.QueryRow(query, roleName, userName.(string)).Scan(&adminOption)
		switch {
		case err == sql.ErrNoRows:
			return false, false, nil
		case err != nil:
			return false, false, err
		}
		return true, adminOption, nil
	}

	granteeRoleName := d.Get(roleGrantGranteeRoleAttr).(string)
	var exists int
	query := "SELECT 1 FROM svv_role_grants WHERE role_name = $1 AND granted_role_name = $2"
	err := db.QueryRow(query, granteeRoleName, roleName).Scan(&exists)
	switch {
	case err == sql.ErrNoRows:
		return false, false, nil
	case err != nil:
		return false, false, err
	}

	return true, false, nil
}

func resourceRedshiftRoleGrantCreate(db *DBConnection, d *schema.ResourceData) error {
	roleName := d.Get(roleGrantRoleAttr).(string)

	query := fmt.Sprintf("GRANT ROLE %s TO ", pq.QuoteIdentifier(roleName))
	if userName, isUser := d.GetOk(roleGrantUserAttr); isUser {
		query = fmt.Sprintf("%s%s", query, pq.QuoteIdentifier(userName.(string)))
		if d.Get(roleGrantAdminOptionAttr).(bool) {
			query = fmt.Sprintf("%s WITH ADMIN OPTION", query)
		}
	} else if granteeRole, isRole := d.GetOk(roleGrantGranteeRoleAttr); isRole {
		query = fmt.Sprintf("%sROLE %s", query, pq.QuoteIdentifier(granteeRole.(string)))
	} else {
		return fmt.Errorf("either %s or %s is required", roleGrantUserAttr, roleGrantGranteeRoleAttr)
	}

	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("error granting role %s: %w", roleName, err)
	}

	d.SetId(generateRoleGrantID(d))

	return resourceRedshiftRoleGrantReadImpl(db, d)
}

func resourceRedshiftRoleGrantRead(db *DBConnection, d *schema.ResourceData) error {
	return resourceRedshiftRoleGrantReadImpl(db, d)
}

func resourceRedshiftRoleGrantReadImpl(db *DBConnection, d *schema.ResourceData) error {
	found, adminOption, err := roleGrantLookup(db, d)
	if err != nil {
		return fmt.Errorf("error reading role grant: %w", err)
	}
	if !found {
		d.SetId("")
		return nil
	}

	if _, isUser := d.GetOk(roleGrantUserAttr); isUser {
		d.Set(roleGrantAdminOptionAttr, adminOption)
	}

	return nil
}

func resourceRedshiftRoleGrantDelete(db *DBConnection, d *schema.ResourceData) error {
	roleName := d.Get(roleGrantRoleAttr).(string)

	query := fmt.Sprintf("REVOKE ROLE %s FROM ", pq.QuoteIdentifier(roleName))
	if userName, isUser := d.GetOk(roleGrantUserAttr); isUser {
		query = fmt.Sprintf("%s%s", query, pq.QuoteIdentifier(userName.(string)))
	} else if granteeRole, isRole := d.GetOk(roleGrantGranteeRoleAttr); isRole {
		query = fmt.Sprintf("%sROLE %s", query, pq.QuoteIdentifier(granteeRole.(string)))
	} else {
		return fmt.Errorf("either %s or %s is required", roleGrantUserAttr, roleGrantGranteeRoleAttr)
	}

	_, err := db.Exec(query)
	return err
}

func generateRoleGrantID(d *schema.ResourceData) string {
	parts := []string{fmt.Sprintf("rn:%s", d.Get(roleGrantRoleAttr).(string))}

	if userName, isUser := d.GetOk(roleGrantUserAttr); isUser {
		parts = append(parts, fmt.Sprintf("un:%s", userName.(string)))
	} else if granteeRole, isRole := d.GetOk(roleGrantGranteeRoleAttr); isRole {
		parts = append(parts, fmt.Sprintf("gr:%s", granteeRole.(string)))
	}

	return strings.Join(parts, "_")
}
