package redshift

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/lib/pq"
)

const (
	scopedGrantUserAttr       = "user"
	scopedGrantRoleAttr       = "role"
	scopedGrantPublicAttr     = "public"
	scopedGrantScopeAttr      = "scope"
	scopedGrantDatabaseAttr   = "database"
	scopedGrantSchemaAttr     = "schema"
	scopedGrantPrivilegesAttr = "privileges"

	// Identity types, as reported in the identity_type column of the SVV_*_PRIVILEGES views.
	scopedGrantIdentityUser   = "user"
	scopedGrantIdentityRole   = "role"
	scopedGrantIdentityPublic = "public"

	pqErrorCodeInvalidCatalogName = "3D000"
)

var scopedGrantAllowedScopes = []string{"schemas", "tables", "functions", "languages", "copy jobs"}

// scopedGrantSchemaScopes lists the scopes that can apply to one schema. All other
// scopes apply only to a full database.
var scopedGrantSchemaScopes = map[string]bool{
	"tables":    true,
	"functions": true,
}

var scopedGrantGranteeAttrs = []string{scopedGrantUserAttr, scopedGrantRoleAttr, scopedGrantPublicAttr}

func redshiftScopedGrant() *schema.Resource {
	return &schema.Resource{
		Description: `
Grants scoped permissions to a user, a role, or PUBLIC. A scoped permission applies to all current and future objects of one type in a database or in a schema, for example ` + "`GRANT SELECT FOR TABLES IN SCHEMA sales DATABASE dev TO ROLE analyst`" + `. See https://docs.aws.amazon.com/redshift/latest/dg/t_scoped-permissions.html.

Scoped permissions are different from ` + "`redshift_default_privileges`" + `. Default privileges apply only to objects that a specified user creates. Scoped permissions apply to all objects in the scope, no matter which user creates them.

This resource manages the full set of privileges for one grantee, scope, and target: applying it revokes all privileges in the scope that are not listed in ` + "`privileges`" + `. Do not use two resources for the same grantee, scope, and target.

Limitations:

- Groups are not supported. Redshift does not accept scoped permissions for groups.
- The ` + "`functions`" + ` scope also applies to stored procedures. Redshift stores ` + "`FOR PROCEDURES`" + ` grants as ` + "`FOR FUNCTIONS`" + ` grants.
- ` + "`all`" + ` is not accepted in ` + "`privileges`" + `. List each privilege instead.
`,
		Create: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftScopedGrantCreate),
		),
		Read: RedshiftResourceFunc(resourceRedshiftScopedGrantRead),
		// Create revokes all privileges in the scope and then grants the configured
		// privileges in one transaction, so it can also be used as update
		Update: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftScopedGrantCreate),
		),
		Delete: RedshiftResourceFunc(
			RedshiftResourceRetryOnPQErrors(resourceRedshiftScopedGrantDelete),
		),
		Importer: &schema.ResourceImporter{
			StateContext: resourceRedshiftScopedGrantImport,
		},
		CustomizeDiff: resourceRedshiftScopedGrantCustomizeDiff,

		Schema: map[string]*schema.Schema{
			scopedGrantUserAttr: {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ExactlyOneOf: scopedGrantGranteeAttrs,
				Description:  "The name of the user to grant the scoped permissions to. Exactly one of `user`, `role`, or `public` must be set.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			scopedGrantRoleAttr: {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				ExactlyOneOf: scopedGrantGranteeAttrs,
				Description:  "The name of the role to grant the scoped permissions to. Exactly one of `user`, `role`, or `public` must be set. Every user or role that this role is granted to (via `redshift_role_grant`) inherits these permissions.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			scopedGrantPublicAttr: {
				Type:         schema.TypeBool,
				Optional:     true,
				ForceNew:     true,
				ExactlyOneOf: scopedGrantGranteeAttrs,
				Description:  "Set to `true` to grant the scoped permissions to PUBLIC, which includes all users. Exactly one of `user`, `role`, or `public` must be set. Only `true` is valid. Do not set `public = false` together with `user` or `role`: Terraform counts it as a second grantee.",
			},
			scopedGrantScopeAttr: {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice(scopedGrantAllowedScopes, false),
				Description:  "The type of objects that the permissions apply to. One of: " + strings.Join(scopedGrantAllowedScopes, ", ") + ". The `functions` scope also applies to stored procedures.",
			},
			scopedGrantDatabaseAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "The database that the permissions apply to. The provider connects to this database to apply the permissions, so the provider user must be able to connect to it. The default is the database of the provider when the resource is created. If you remove this attribute or change the provider database later, the permissions stay in the database where they were created.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			scopedGrantSchemaAttr: {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The schema that the permissions apply to. Valid only when `scope` is `tables` or `functions`. If you do not set it, the permissions apply to the full database.",
				StateFunc: func(val interface{}) string {
					return strings.ToLower(val.(string))
				},
			},
			scopedGrantPrivilegesAttr: {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					StateFunc: func(val interface{}) string {
						return strings.ToLower(strings.TrimSpace(val.(string)))
					},
				},
				Set:         schema.HashString,
				Description: "The privileges to grant. Valid values for each scope: `schemas`: create, usage, alter, drop. `tables`: select, insert, update, delete, drop, alter, truncate, references. `functions`: execute. `languages`: usage. `copy jobs`: create, alter, drop. An empty list revokes all privileges in the scope.",
			},
		},
	}
}

// scopedGrant identifies the grantee, scope, and target of a scoped permission.
type scopedGrant struct {
	// identityType is one of scopedGrantIdentityUser, scopedGrantIdentityRole, or
	// scopedGrantIdentityPublic.
	identityType string
	// identityName is the lowercase user or role name, or "public".
	identityName string
	scope        string
	database     string
	// schema is empty when the permissions apply to the full database.
	schema string
}

func scopedGrantFromResourceData(d *schema.ResourceData) scopedGrant {
	// Redshift folds identifiers to lowercase, and the system views report them in
	// lowercase. The StateFunc of each name attribute changes only the stored value,
	// so lowercase all names here too.
	g := scopedGrant{
		scope:    d.Get(scopedGrantScopeAttr).(string),
		database: strings.ToLower(d.Get(scopedGrantDatabaseAttr).(string)),
		schema:   strings.ToLower(d.Get(scopedGrantSchemaAttr).(string)),
	}

	if user, ok := d.GetOk(scopedGrantUserAttr); ok {
		g.identityType = scopedGrantIdentityUser
		g.identityName = strings.ToLower(user.(string))
	} else if role, ok := d.GetOk(scopedGrantRoleAttr); ok {
		g.identityType = scopedGrantIdentityRole
		g.identityName = strings.ToLower(role.(string))
	} else {
		g.identityType = scopedGrantIdentityPublic
		g.identityName = scopedGrantIdentityPublic
	}

	return g
}

// id returns the resource ID, in the form
// <identity_type>:<identity_name>/<scope>/<database>[/<schema>].
// The ID uses "/" as a separator because names often contain "_".
func (g scopedGrant) id() string {
	parts := []string{fmt.Sprintf("%s:%s", g.identityType, g.identityName), g.scope, g.database}
	if g.schema != "" {
		parts = append(parts, g.schema)
	}
	return strings.Join(parts, "/")
}

func parseScopedGrantID(id string) (scopedGrant, error) {
	format := "<user|role|public>:<name>/<scope>/<database>[/<schema>]"

	parts := strings.Split(id, "/")
	if len(parts) != 3 && len(parts) != 4 {
		return scopedGrant{}, fmt.Errorf("invalid ID %q, expected format %s", id, format)
	}

	identity := strings.SplitN(parts[0], ":", 2)
	if len(identity) != 2 || identity[1] == "" {
		return scopedGrant{}, fmt.Errorf("invalid grantee %q in ID %q, expected format %s", parts[0], id, format)
	}

	g := scopedGrant{
		identityType: identity[0],
		identityName: strings.ToLower(identity[1]),
		scope:        parts[1],
		database:     strings.ToLower(parts[2]),
	}
	if len(parts) == 4 {
		g.schema = strings.ToLower(parts[3])
	}

	switch g.identityType {
	case scopedGrantIdentityUser, scopedGrantIdentityRole:
	case scopedGrantIdentityPublic:
		if g.identityName != scopedGrantIdentityPublic {
			return scopedGrant{}, fmt.Errorf("invalid grantee %q in ID %q, use public:public for PUBLIC", parts[0], id)
		}
	default:
		return scopedGrant{}, fmt.Errorf("invalid grantee type %q in ID %q, expected one of user, role, public", g.identityType, id)
	}

	if _, ok := scopedGrantPrivileges[g.scope]; !ok {
		return scopedGrant{}, fmt.Errorf("invalid scope %q in ID %q, expected one of %s", g.scope, id, strings.Join(scopedGrantAllowedScopes, ", "))
	}
	if g.database == "" {
		return scopedGrant{}, fmt.Errorf("missing database in ID %q, expected format %s", id, format)
	}
	if len(parts) == 4 && g.schema == "" {
		return scopedGrant{}, fmt.Errorf("empty schema in ID %q, expected format %s", id, format)
	}
	if err := validateScopedGrantSchema(g.scope, g.schema); err != nil {
		return scopedGrant{}, fmt.Errorf("invalid ID %q: %w", id, err)
	}

	return g, nil
}

// validateScopedGrantSchema returns an error if a schema is set for a scope that
// applies only to a full database.
func validateScopedGrantSchema(scope, schemaName string) error {
	if schemaName != "" && !scopedGrantSchemaScopes[scope] {
		return fmt.Errorf("`%s` can't be set when `%s` is %q, because this scope applies only to a full database", scopedGrantSchemaAttr, scopedGrantScopeAttr, scope)
	}
	return nil
}

// privilegeScope returns the value of the privilege_scope column in the
// SVV_*_PRIVILEGES views for this scope.
func (g scopedGrant) privilegeScope() string {
	return strings.ToUpper(g.scope)
}

func (g scopedGrant) granteeSQL() string {
	switch g.identityType {
	case scopedGrantIdentityRole:
		return "ROLE " + pq.QuoteIdentifier(g.identityName)
	case scopedGrantIdentityPublic:
		return "PUBLIC"
	default:
		return pq.QuoteIdentifier(g.identityName)
	}
}

func (g scopedGrant) targetSQL() string {
	if g.schema != "" {
		return fmt.Sprintf("SCHEMA %s DATABASE %s", pq.QuoteIdentifier(g.schema), pq.QuoteIdentifier(g.database))
	}
	return fmt.Sprintf("DATABASE %s", pq.QuoteIdentifier(g.database))
}

// buildScopedGrantQueries returns the statement that revokes all privileges in the
// scope, and the statement that grants the privileges. The grant statement is empty
// when there are no privileges to grant.
func buildScopedGrantQueries(g scopedGrant, privileges []string) (revoke string, grant string) {
	revoke = fmt.Sprintf("REVOKE ALL FOR %s IN %s FROM %s", g.privilegeScope(), g.targetSQL(), g.granteeSQL())

	if len(privileges) == 0 {
		return revoke, ""
	}

	upper := make([]string, len(privileges))
	for i, p := range privileges {
		upper[i] = strings.ToUpper(p)
	}
	sort.Strings(upper)

	grant = fmt.Sprintf("GRANT %s FOR %s IN %s TO %s", strings.Join(upper, ", "), g.privilegeScope(), g.targetSQL(), g.granteeSQL())
	return revoke, grant
}

func scopedGrantPrivilegesFromResourceData(d *schema.ResourceData) []string {
	privileges := []string{}
	for _, p := range d.Get(scopedGrantPrivilegesAttr).(*schema.Set).List() {
		privileges = append(privileges, strings.ToLower(strings.TrimSpace(p.(string))))
	}
	return privileges
}

func resourceRedshiftScopedGrantCustomizeDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	// ExactlyOneOf makes sure that one grantee attribute is set. If it is public,
	// it must also be true. Skip the check while user or role is not known yet.
	if d.NewValueKnown(scopedGrantUserAttr) && d.NewValueKnown(scopedGrantRoleAttr) && d.NewValueKnown(scopedGrantPublicAttr) {
		_, hasUser := d.GetOk(scopedGrantUserAttr)
		_, hasRole := d.GetOk(scopedGrantRoleAttr)
		if !hasUser && !hasRole && !d.Get(scopedGrantPublicAttr).(bool) {
			return fmt.Errorf("`%s` must be true when it is set, or set `%s` or `%s` instead", scopedGrantPublicAttr, scopedGrantUserAttr, scopedGrantRoleAttr)
		}
	}

	// The scope decides which schema and privileges are valid. Create validates
	// again when the scope is known.
	if !d.NewValueKnown(scopedGrantScopeAttr) {
		return nil
	}
	scope := d.Get(scopedGrantScopeAttr).(string)

	if d.NewValueKnown(scopedGrantSchemaAttr) {
		if err := validateScopedGrantSchema(scope, d.Get(scopedGrantSchemaAttr).(string)); err != nil {
			return err
		}
	}

	if d.NewValueKnown(scopedGrantPrivilegesAttr) {
		privileges := []string{}
		for _, p := range d.Get(scopedGrantPrivilegesAttr).(*schema.Set).List() {
			privileges = append(privileges, p.(string))
		}
		if err := validateScopedPrivileges(privileges, scope); err != nil {
			return err
		}
	}

	return nil
}

func resourceRedshiftScopedGrantCreate(db *DBConnection, d *schema.ResourceData) error {
	if d.Get(scopedGrantDatabaseAttr).(string) == "" {
		// d.Set does not run the StateFunc, so lowercase the name here.
		d.Set(scopedGrantDatabaseAttr, strings.ToLower(db.client.databaseName))
	}

	g := scopedGrantFromResourceData(d)
	privileges := scopedGrantPrivilegesFromResourceData(d)

	// CustomizeDiff skips the validation when a value is not known at plan time.
	if err := validateScopedGrantSchema(g.scope, g.schema); err != nil {
		return err
	}
	if err := validateScopedPrivileges(privileges, g.scope); err != nil {
		return err
	}

	// Without this check, a missing object gives an error from REVOKE that the retry
	// wrapper retries for almost a minute, and the error message is less clear.
	conn, err := db.client.config.NewClient(g.database).Connect()
	if err != nil {
		return err
	}
	missing, err := findMissingScopedGrantObject(conn, g)
	if err != nil {
		return fmt.Errorf("error checking scoped grant %s: %w", g.id(), err)
	}
	if missing != "" {
		return fmt.Errorf("could not apply scoped grant %s: %s", g.id(), missing)
	}

	revoke, grant := buildScopedGrantQueries(g, privileges)

	tx, err := startTransaction(db.client, g.database)
	if err != nil {
		return err
	}
	defer deferredRollback(tx)

	log.Printf("[DEBUG] Revoking scoped permissions: %s", revoke)
	if _, err := tx.Exec(revoke); err != nil {
		return fmt.Errorf("error revoking scoped permissions for %s: %w", g.id(), err)
	}

	if grant != "" {
		log.Printf("[DEBUG] Granting scoped permissions: %s", grant)
		if _, err := tx.Exec(grant); err != nil {
			return fmt.Errorf("error granting scoped permissions for %s: %w", g.id(), err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	d.SetId(g.id())

	return resourceRedshiftScopedGrantReadImpl(db, d, true)
}

func resourceRedshiftScopedGrantRead(db *DBConnection, d *schema.ResourceData) error {
	return resourceRedshiftScopedGrantReadImpl(db, d, false)
}

// resourceRedshiftScopedGrantReadImpl reads the privileges of the scoped grant. If the
// grantee, schema, or database does not exist, it removes the resource from state.
// After a write (afterWrite is true), it returns an error instead, because a missing
// object at that time shows a provider error, not a change outside Terraform.
func resourceRedshiftScopedGrantReadImpl(db *DBConnection, d *schema.ResourceData, afterWrite bool) error {
	g := scopedGrantFromResourceData(d)

	// SVV_SCHEMA_PRIVILEGES shows only the schemas of the current database, so
	// connect to the target database for all reads.
	conn, err := db.client.config.NewClient(g.database).Connect()
	if err != nil {
		return err
	}

	missing, err := findMissingScopedGrantObject(conn, g)
	if err != nil {
		return fmt.Errorf("error reading scoped grant %s: %w", g.id(), err)
	}
	if missing != "" {
		if afterWrite {
			return fmt.Errorf("could not read scoped grant %s after the write: %s", g.id(), missing)
		}
		log.Printf("[WARN] %s, removing scoped grant %s from state", missing, g.id())
		d.SetId("")
		return nil
	}

	var query string
	var args []interface{}

	if g.schema != "" {
		query = "SELECT privilege_type FROM svv_schema_privileges WHERE namespace_name = $1 AND privilege_scope = $2 AND identity_type = $3 AND identity_name = $4"
		args = []interface{}{g.schema, g.privilegeScope(), g.identityType, g.identityName}
	} else {
		query = "SELECT privilege_type FROM svv_database_privileges WHERE database_name = $1 AND privilege_scope = $2 AND identity_type = $3 AND identity_name = $4"
		args = []interface{}{g.database, g.privilegeScope(), g.identityType, g.identityName}
	}

	log.Printf("[DEBUG] Reading scoped grant %s: %s", g.id(), query)

	rows, err := conn.Query(query, args...)
	if err != nil {
		return fmt.Errorf("error reading scoped grant %s: %w", g.id(), err)
	}
	defer rows.Close()

	privileges := []interface{}{}
	for rows.Next() {
		var privilege string
		if err := rows.Scan(&privilege); err != nil {
			return err
		}
		privileges = append(privileges, privilege)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// An empty set is a valid configuration, so a scope without privileges stays in state.
	d.Set(scopedGrantPrivilegesAttr, normalizeRolePrivileges(privileges))

	return nil
}

// findMissingScopedGrantObject returns a description of the first object of the
// scoped grant that does not exist: the database, the grantee, or the schema. It
// returns an empty string if all objects exist. conn must be a connection to the
// target database.
func findMissingScopedGrantObject(conn *DBConnection, g scopedGrant) (string, error) {
	type existenceCheck struct {
		query   string
		args    []interface{}
		missing string
	}

	checks := []existenceCheck{}
	switch g.identityType {
	case scopedGrantIdentityRole:
		checks = append(checks, existenceCheck{
			"SELECT EXISTS (SELECT 1 FROM svv_roles WHERE role_name = $1)",
			[]interface{}{g.identityName},
			fmt.Sprintf("role %s does not exist", g.identityName),
		})
	case scopedGrantIdentityUser:
		checks = append(checks, existenceCheck{
			"SELECT EXISTS (SELECT 1 FROM pg_user WHERE usename = $1)",
			[]interface{}{g.identityName},
			fmt.Sprintf("user %s does not exist", g.identityName),
		})
	}
	if g.schema != "" {
		checks = append(checks, existenceCheck{
			"SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)",
			[]interface{}{g.schema},
			fmt.Sprintf("schema %s does not exist in database %s", g.schema, g.database),
		})
	}
	// Each query also finds out if the target database exists. A grant to PUBLIC at
	// database level has no other object to check, so it needs one query for that.
	if len(checks) == 0 {
		checks = append(checks, existenceCheck{query: "SELECT TRUE"})
	}

	for _, check := range checks {
		var exists bool
		err := conn.QueryRow(check.query, check.args...).Scan(&exists)
		if isPQErrorCode(err, pqErrorCodeInvalidCatalogName) {
			return fmt.Sprintf("database %s does not exist", g.database), nil
		}
		if err != nil {
			return "", err
		}
		if !exists {
			return check.missing, nil
		}
	}

	return "", nil
}

func isPQErrorCode(err error, code string) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && string(pqErr.Code) == code
}

func resourceRedshiftScopedGrantDelete(db *DBConnection, d *schema.ResourceData) error {
	g := scopedGrantFromResourceData(d)
	revoke, _ := buildScopedGrantQueries(g, nil)

	// If the grantee, schema, or database no longer exists, Redshift has already
	// removed the privileges, and REVOKE would fail.
	conn, err := db.client.config.NewClient(g.database).Connect()
	if err != nil {
		return err
	}
	missing, err := findMissingScopedGrantObject(conn, g)
	if err != nil {
		return fmt.Errorf("error deleting scoped grant %s: %w", g.id(), err)
	}
	if missing != "" {
		log.Printf("[WARN] %s, so there is nothing to revoke for scoped grant %s", missing, g.id())
		return nil
	}

	tx, err := startTransaction(db.client, g.database)
	if err != nil {
		return err
	}
	defer deferredRollback(tx)

	log.Printf("[DEBUG] Revoking scoped permissions: %s", revoke)
	if _, err := tx.Exec(revoke); err != nil {
		return fmt.Errorf("error revoking scoped permissions for %s: %w", g.id(), err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("could not commit transaction: %w", err)
	}

	return nil
}

func resourceRedshiftScopedGrantImport(_ context.Context, d *schema.ResourceData, _ interface{}) ([]*schema.ResourceData, error) {
	g, err := parseScopedGrantID(d.Id())
	if err != nil {
		return nil, err
	}

	switch g.identityType {
	case scopedGrantIdentityUser:
		d.Set(scopedGrantUserAttr, g.identityName)
	case scopedGrantIdentityRole:
		d.Set(scopedGrantRoleAttr, g.identityName)
	case scopedGrantIdentityPublic:
		d.Set(scopedGrantPublicAttr, true)
	}
	d.Set(scopedGrantScopeAttr, g.scope)
	d.Set(scopedGrantDatabaseAttr, g.database)
	if g.schema != "" {
		d.Set(scopedGrantSchemaAttr, g.schema)
	}
	d.SetId(g.id())

	return []*schema.ResourceData{d}, nil
}
