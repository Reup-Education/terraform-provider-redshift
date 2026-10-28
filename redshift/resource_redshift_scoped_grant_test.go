package redshift

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/lib/pq"
)

func TestScopedGrantID(t *testing.T) {
	tests := map[string]struct {
		grant scopedGrant
		id    string
	}{
		"role with schema": {
			grant: scopedGrant{identityType: "role", identityName: "analyst", scope: "tables", database: "dev", schema: "sales"},
			id:    "role:analyst/tables/dev/sales",
		},
		"user with database": {
			grant: scopedGrant{identityType: "user", identityName: "bob", scope: "schemas", database: "dev"},
			id:    "user:bob/schemas/dev",
		},
		"public with copy jobs": {
			grant: scopedGrant{identityType: "public", identityName: "public", scope: "copy jobs", database: "dev"},
			id:    "public:public/copy jobs/dev",
		},
		"names with underscores": {
			grant: scopedGrant{identityType: "role", identityName: "my_role", scope: "functions", database: "my_db", schema: "my_schema"},
			id:    "role:my_role/functions/my_db/my_schema",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tt.grant.id(); got != tt.id {
				t.Fatalf("expected ID %q, got %q", tt.id, got)
			}

			parsed, err := parseScopedGrantID(tt.id)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if parsed != tt.grant {
				t.Fatalf("expected %+v, got %+v", tt.grant, parsed)
			}
		})
	}
}

func TestParseScopedGrantIDErrors(t *testing.T) {
	tests := map[string]string{
		"too few parts":           "role:analyst/tables",
		"too many parts":          "role:analyst/tables/dev/sales/extra",
		"no grantee separator":    "analyst/tables/dev",
		"empty grantee name":      "role:/tables/dev",
		"unknown grantee type":    "group:analysts/tables/dev",
		"public with other name":  "public:everyone/tables/dev",
		"unknown scope":           "role:analyst/views/dev",
		"procedures scope":        "role:analyst/procedures/dev",
		"empty database":          "role:analyst/tables/",
		"empty schema":            "role:analyst/tables/dev/",
		"schema on database only": "role:analyst/schemas/dev/sales",
	}

	for name, id := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseScopedGrantID(id); err == nil {
				t.Fatalf("expected an error for ID %q", id)
			}
		})
	}
}

func TestParseScopedGrantIDLowercase(t *testing.T) {
	got, err := parseScopedGrantID("role:Analyst/tables/DEV/Sales")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	want := scopedGrant{identityType: "role", identityName: "analyst", scope: "tables", database: "dev", schema: "sales"}
	if got != want {
		t.Fatalf("expected %+v, got %+v", want, got)
	}
}

func TestValidateScopedGrantSchema(t *testing.T) {
	for _, scope := range scopedGrantAllowedScopes {
		if err := validateScopedGrantSchema(scope, ""); err != nil {
			t.Fatalf("scope %q without schema: unexpected error: %s", scope, err)
		}

		err := validateScopedGrantSchema(scope, "sales")
		if scopedGrantSchemaScopes[scope] && err != nil {
			t.Fatalf("scope %q with schema: unexpected error: %s", scope, err)
		}
		if !scopedGrantSchemaScopes[scope] && err == nil {
			t.Fatalf("scope %q with schema: expected an error", scope)
		}
	}
}

func TestBuildScopedGrantQueries(t *testing.T) {
	tests := map[string]struct {
		grant      scopedGrant
		privileges []string
		revoke     string
		grantSQL   string
	}{
		"role with schema": {
			grant:      scopedGrant{identityType: "role", identityName: "analyst", scope: "tables", database: "dev", schema: "sales"},
			privileges: []string{"select", "insert"},
			revoke:     `REVOKE ALL FOR TABLES IN SCHEMA "sales" DATABASE "dev" FROM ROLE "analyst"`,
			grantSQL:   `GRANT INSERT, SELECT FOR TABLES IN SCHEMA "sales" DATABASE "dev" TO ROLE "analyst"`,
		},
		"user with database": {
			grant:      scopedGrant{identityType: "user", identityName: "bob", scope: "schemas", database: "dev"},
			privileges: []string{"usage"},
			revoke:     `REVOKE ALL FOR SCHEMAS IN DATABASE "dev" FROM "bob"`,
			grantSQL:   `GRANT USAGE FOR SCHEMAS IN DATABASE "dev" TO "bob"`,
		},
		"public with copy jobs": {
			grant:      scopedGrant{identityType: "public", identityName: "public", scope: "copy jobs", database: "dev"},
			privileges: []string{"alter", "drop"},
			revoke:     `REVOKE ALL FOR COPY JOBS IN DATABASE "dev" FROM PUBLIC`,
			grantSQL:   `GRANT ALTER, DROP FOR COPY JOBS IN DATABASE "dev" TO PUBLIC`,
		},
		"no privileges": {
			grant:      scopedGrant{identityType: "role", identityName: "analyst", scope: "functions", database: "dev", schema: "sales"},
			privileges: []string{},
			revoke:     `REVOKE ALL FOR FUNCTIONS IN SCHEMA "sales" DATABASE "dev" FROM ROLE "analyst"`,
			grantSQL:   "",
		},
		"names that need quotes": {
			grant:      scopedGrant{identityType: "role", identityName: `odd"role`, scope: "tables", database: "my-db", schema: "My Schema"},
			privileges: []string{"select"},
			revoke:     `REVOKE ALL FOR TABLES IN SCHEMA "My Schema" DATABASE "my-db" FROM ROLE "odd""role"`,
			grantSQL:   `GRANT SELECT FOR TABLES IN SCHEMA "My Schema" DATABASE "my-db" TO ROLE "odd""role"`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			revoke, grant := buildScopedGrantQueries(tt.grant, tt.privileges)
			if revoke != tt.revoke {
				t.Fatalf("expected revoke\n  %s\ngot\n  %s", tt.revoke, revoke)
			}
			if grant != tt.grantSQL {
				t.Fatalf("expected grant\n  %s\ngot\n  %s", tt.grantSQL, grant)
			}
		})
	}
}

func TestAccRedshiftScopedGrant_RoleScopes(t *testing.T) {
	roleName := strings.ReplaceAll(acctest.RandomWithPrefix("tf_acc_role"), "-", "_")
	schemaName := strings.ReplaceAll(acctest.RandomWithPrefix("tf_acc_schema"), "-", "_")

	baseConfig := fmt.Sprintf(`
resource "redshift_role" "role" {
  name          = %[1]q
  force_destroy = true
}

resource "redshift_schema" "schema" {
  name              = %[2]q
  cascade_on_delete = true
}
`, roleName, schemaName)

	config := func(tablePrivileges []string) string {
		return baseConfig + fmt.Sprintf(`
resource "redshift_scoped_grant" "schemas" {
  role       = redshift_role.role.name
  scope      = "schemas"
  privileges = ["usage", "create"]
}

# The uppercase schema name must match the lowercase name that Redshift stores.
resource "redshift_scoped_grant" "tables_schema" {
  role       = redshift_role.role.name
  scope      = "tables"
  schema     = upper(redshift_schema.schema.name)
  privileges = %[1]s
}

resource "redshift_scoped_grant" "tables_database" {
  role       = redshift_role.role.name
  scope      = "tables"
  privileges = ["select"]
}

resource "redshift_scoped_grant" "functions" {
  role       = redshift_role.role.name
  scope      = "functions"
  schema     = redshift_schema.schema.name
  privileges = ["execute"]
}

resource "redshift_scoped_grant" "languages" {
  role       = redshift_role.role.name
  scope      = "languages"
  privileges = ["usage"]
}

resource "redshift_scoped_grant" "copy_jobs" {
  role       = redshift_role.role.name
  scope      = "copy jobs"
  privileges = ["alter"]
}
`, tfArray(tablePrivileges))
	}

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config([]string{"select", "insert"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("redshift_scoped_grant.schemas", "id", regexp.MustCompile(fmt.Sprintf("^role:%s/schemas/[^/]+$", roleName))),
					resource.TestCheckResourceAttrSet("redshift_scoped_grant.schemas", "database"),
					resource.TestCheckResourceAttr("redshift_scoped_grant.schemas", "privileges.#", "2"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.schemas", "privileges.*", "usage"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.schemas", "privileges.*", "create"),

					resource.TestMatchResourceAttr("redshift_scoped_grant.tables_schema", "id", regexp.MustCompile(fmt.Sprintf("^role:%s/tables/[^/]+/%s$", roleName, schemaName))),
					resource.TestCheckResourceAttr("redshift_scoped_grant.tables_schema", "schema", schemaName),
					resource.TestCheckResourceAttr("redshift_scoped_grant.tables_schema", "privileges.#", "2"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.tables_schema", "privileges.*", "select"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.tables_schema", "privileges.*", "insert"),

					// The database-level and schema-level tables scopes must not see the
					// privileges of each other.
					resource.TestCheckResourceAttr("redshift_scoped_grant.tables_database", "privileges.#", "1"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.tables_database", "privileges.*", "select"),

					resource.TestCheckResourceAttr("redshift_scoped_grant.functions", "privileges.#", "1"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.functions", "privileges.*", "execute"),

					resource.TestCheckResourceAttr("redshift_scoped_grant.languages", "privileges.#", "1"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.languages", "privileges.*", "usage"),

					resource.TestCheckResourceAttr("redshift_scoped_grant.copy_jobs", "privileges.#", "1"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.copy_jobs", "privileges.*", "alter"),
				),
			},
			{
				Config: config([]string{"select", "insert", "update"}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("redshift_scoped_grant.tables_schema", "privileges.#", "3"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.tables_schema", "privileges.*", "update"),
					resource.TestCheckResourceAttr("redshift_scoped_grant.tables_database", "privileges.#", "1"),
				),
			},
			{
				Config: config([]string{}),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("redshift_scoped_grant.tables_schema", "privileges.#", "0"),
					resource.TestCheckResourceAttr("redshift_scoped_grant.tables_database", "privileges.#", "1"),
				),
			},
			{
				ResourceName:      "redshift_scoped_grant.tables_schema",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				ResourceName:      "redshift_scoped_grant.copy_jobs",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Remove only the scoped grants. The role and schema stay, so the
				// privileges can only disappear if Delete revokes them.
				Config: baseConfig,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRedshiftNoScopedPrivileges("role", roleName, ""),
					testAccCheckRedshiftNoScopedPrivileges("role", roleName, schemaName),
				),
			},
		},
	})
}

func TestAccRedshiftScopedGrant_UserFutureTables(t *testing.T) {
	userName := strings.ReplaceAll(acctest.RandomWithPrefix("tf_acc_user"), "-", "_")
	schemaName := strings.ReplaceAll(acctest.RandomWithPrefix("tf_acc_schema"), "-", "_")
	tableName := "created_after_grant"

	config := fmt.Sprintf(`
resource "redshift_user" "user" {
  name     = %[1]q
  password = "Foo123456$"
}

resource "redshift_schema" "schema" {
  name              = %[2]q
  cascade_on_delete = true
}

resource "redshift_scoped_grant" "tables" {
  user       = redshift_user.user.name
  scope      = "tables"
  schema     = redshift_schema.schema.name
  privileges = ["select"]
}
`, userName, schemaName)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("redshift_scoped_grant.tables", "id", regexp.MustCompile(fmt.Sprintf("^user:%s/tables/[^/]+/%s$", userName, schemaName))),
					resource.TestCheckResourceAttr("redshift_scoped_grant.tables", "privileges.#", "1"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.tables", "privileges.*", "select"),
				),
			},
			{
				// The table is created after the grant. The schema has cascade_on_delete,
				// so the destroy also drops the table.
				PreConfig: func() {
					testAccRedshiftScopedGrantExec(t, fmt.Sprintf("CREATE TABLE %s.%s (id int)", pq.QuoteIdentifier(schemaName), pq.QuoteIdentifier(tableName)))
				},
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testAccCheckRedshiftHasTablePrivilege(userName, schemaName, tableName, "select", true),
					testAccCheckRedshiftHasTablePrivilege(userName, schemaName, tableName, "insert", false),
				),
			},
			{
				ResourceName:      "redshift_scoped_grant.tables",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccRedshiftScopedGrant_Public(t *testing.T) {
	schemaName := strings.ReplaceAll(acctest.RandomWithPrefix("tf_acc_schema"), "-", "_")

	baseConfig := fmt.Sprintf(`
resource "redshift_schema" "schema" {
  name              = %[1]q
  cascade_on_delete = true
}
`, schemaName)

	config := baseConfig + `
resource "redshift_scoped_grant" "public" {
  public     = true
  scope      = "tables"
  schema     = redshift_schema.schema.name
  privileges = ["select"]
}
`

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestMatchResourceAttr("redshift_scoped_grant.public", "id", regexp.MustCompile(fmt.Sprintf("^public:public/tables/[^/]+/%s$", schemaName))),
					resource.TestCheckResourceAttr("redshift_scoped_grant.public", "public", "true"),
					resource.TestCheckResourceAttr("redshift_scoped_grant.public", "privileges.#", "1"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.public", "privileges.*", "select"),
				),
			},
			{
				ResourceName:      "redshift_scoped_grant.public",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Remove only the scoped grant. The schema stays, so the privileges can
				// only disappear if Delete revokes them.
				Config: baseConfig,
				Check:  testAccCheckRedshiftNoScopedPrivileges("public", "public", schemaName),
			},
		},
	})
}

// TestAccRedshiftScopedGrant_OtherDatabase needs a second database that already exists
// on the cluster. Set REDSHIFT_SCOPED_GRANT_OTHER_DATABASE to its name to run the test.
func TestAccRedshiftScopedGrant_OtherDatabase(t *testing.T) {
	otherDatabase := getEnvOrSkip("REDSHIFT_SCOPED_GRANT_OTHER_DATABASE", t)
	roleName := strings.ReplaceAll(acctest.RandomWithPrefix("tf_acc_role"), "-", "_")

	config := fmt.Sprintf(`
resource "redshift_role" "role" {
  name          = %[1]q
  force_destroy = true
}

resource "redshift_scoped_grant" "schemas" {
  role       = redshift_role.role.name
  scope      = "schemas"
  database   = %[2]q
  privileges = ["usage"]
}
`, roleName, otherDatabase)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("redshift_scoped_grant.schemas", "id", fmt.Sprintf("role:%s/schemas/%s", roleName, otherDatabase)),
					resource.TestCheckResourceAttr("redshift_scoped_grant.schemas", "database", otherDatabase),
					resource.TestCheckResourceAttr("redshift_scoped_grant.schemas", "privileges.#", "1"),
					resource.TestCheckTypeSetElemAttr("redshift_scoped_grant.schemas", "privileges.*", "usage"),
				),
			},
			{
				ResourceName:      "redshift_scoped_grant.schemas",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccRedshiftScopedGrant_MissingObjects drops the schema, and then the grantee,
// outside Terraform. The read must then remove each scoped grant from state, and
// creating the grant again must fail with a clear error.
func TestAccRedshiftScopedGrant_MissingObjects(t *testing.T) {
	roleName := strings.ReplaceAll(acctest.RandomWithPrefix("tf_acc_role"), "-", "_")
	schemaName := strings.ReplaceAll(acctest.RandomWithPrefix("tf_acc_schema"), "-", "_")
	quotedRole := pq.QuoteIdentifier(roleName)
	quotedSchema := pq.QuoteIdentifier(schemaName)

	// The role and the schema are created outside Terraform, so that Terraform cannot
	// drop them before it deletes the scoped grants. Drop them here if a step fails.
	t.Cleanup(func() {
		testAccRedshiftScopedGrantExecIgnoreErrors(
			fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", quotedSchema),
			fmt.Sprintf("REVOKE ALL FOR SCHEMAS IN DATABASE %%s FROM ROLE %s", quotedRole),
			fmt.Sprintf("DROP ROLE %s FORCE", quotedRole),
		)
	})

	schemasGrant := fmt.Sprintf(`
resource "redshift_scoped_grant" "schemas" {
  role       = %[1]q
  scope      = "schemas"
  privileges = ["usage"]
}
`, roleName)

	tablesGrant := fmt.Sprintf(`
resource "redshift_scoped_grant" "tables" {
  role       = %[1]q
  scope      = "tables"
  schema     = %[2]q
  privileges = ["select"]
}
`, roleName, schemaName)

	// Each grant has privileges = [] in the steps after a drop. If the read keeps the
	// grant in state, its empty privileges match the config, the plan is empty, and
	// the step fails because the expected error does not occur. If the read removes
	// the grant from state, Terraform creates it again, and the create fails because
	// the object is missing.
	emptyTablesGrant := strings.Replace(tablesGrant, `["select"]`, "[]", 1)
	emptySchemasGrant := strings.Replace(schemasGrant, `["usage"]`, "[]", 1)

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					testAccRedshiftScopedGrantExec(t, fmt.Sprintf("CREATE ROLE %s", quotedRole))
					testAccRedshiftScopedGrantExec(t, fmt.Sprintf("CREATE SCHEMA %s", quotedSchema))
				},
				Config: schemasGrant + tablesGrant,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("redshift_scoped_grant.schemas", "privileges.#", "1"),
					resource.TestCheckResourceAttr("redshift_scoped_grant.tables", "privileges.#", "1"),
				),
			},
			{
				PreConfig: func() {
					testAccRedshiftScopedGrantExec(t, fmt.Sprintf("DROP SCHEMA %s CASCADE", quotedSchema))
				},
				Config:      schemasGrant + emptyTablesGrant,
				ExpectError: regexp.MustCompile(fmt.Sprintf("schema %s does not exist", schemaName)),
			},
			{
				PreConfig: func() {
					db := pq.QuoteIdentifier(testAccProvider.Meta().(*Client).databaseName)
					testAccRedshiftScopedGrantExec(t, fmt.Sprintf("REVOKE ALL FOR SCHEMAS IN DATABASE %s FROM ROLE %s", db, quotedRole))
					testAccRedshiftScopedGrantExec(t, fmt.Sprintf("DROP ROLE %s", quotedRole))
				},
				Config:      emptySchemasGrant,
				ExpectError: regexp.MustCompile(fmt.Sprintf("role %s does not exist", roleName)),
			},
		},
	})
}

// TestAccRedshiftScopedGrant_InvalidConfig uses only plan steps, so it does not
// create objects on the cluster.
func TestAccRedshiftScopedGrant_InvalidConfig(t *testing.T) {
	config := func(body string) string {
		return fmt.Sprintf(`
resource "redshift_scoped_grant" "invalid" {
%s
}
`, body)
	}

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: config(`
  role       = "tf_acc_role_invalid"
  scope      = "schemas"
  schema     = "sales"
  privileges = ["usage"]
`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("applies only to a full database"),
			},
			{
				Config: config(`
  role       = "tf_acc_role_invalid"
  scope      = "tables"
  privileges = ["all"]
`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("list each privilege instead"),
			},
			{
				Config: config(`
  role       = "tf_acc_role_invalid"
  scope      = "functions"
  privileges = ["select"]
`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`privilege "select" is not valid for scope "functions"`),
			},
			{
				Config: config(`
  public     = false
  scope      = "tables"
  privileges = ["select"]
`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("`public` must be true"),
			},
			{
				Config: config(`
  role       = "tf_acc_role_invalid"
  user       = "tf_acc_user_invalid"
  scope      = "tables"
  privileges = ["select"]
`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("only one of"),
			},
		},
	})
}

// testAccCheckRedshiftNoScopedPrivileges makes sure that the identity has no scoped
// privileges in the schema, or at database level in the provider database if
// schemaName is empty.
func testAccCheckRedshiftNoScopedPrivileges(identityType, identityName, schemaName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testAccProvider.Meta().(*Client)
		conn, err := client.Connect()
		if err != nil {
			return err
		}

		query := "SELECT COUNT(*) FROM svv_database_privileges WHERE database_name = $1 AND privilege_scope <> 'DATABASE' AND identity_type = $2 AND identity_name = $3"
		args := []interface{}{client.databaseName, identityType, identityName}
		if schemaName != "" {
			query = "SELECT COUNT(*) FROM svv_schema_privileges WHERE namespace_name = $1 AND privilege_scope <> 'SCHEMA' AND identity_type = $2 AND identity_name = $3"
			args = []interface{}{schemaName, identityType, identityName}
		}

		var count int
		if err := conn.QueryRow(query, args...).Scan(&count); err != nil {
			return fmt.Errorf("error counting scoped privileges for %s %s: %w", identityType, identityName, err)
		}
		if count > 0 {
			return fmt.Errorf("%s %s still has %d scoped privileges (schema %q) after the scoped grants were removed", identityType, identityName, count, schemaName)
		}

		return nil
	}
}

func testAccCheckRedshiftHasTablePrivilege(userName, schemaName, tableName, privilege string, expected bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client := testAccProvider.Meta().(*Client)
		conn, err := client.Connect()
		if err != nil {
			return err
		}

		table := fmt.Sprintf("%s.%s", pq.QuoteIdentifier(schemaName), pq.QuoteIdentifier(tableName))
		var actual bool
		if err := conn.QueryRow("SELECT has_table_privilege($1, $2, $3)", userName, table, privilege).Scan(&actual); err != nil {
			return fmt.Errorf("error checking %s privilege on %s for %s: %w", privilege, table, userName, err)
		}
		if actual != expected {
			return fmt.Errorf("expected has_table_privilege(%s, %s, %s) to be %t, got %t", userName, table, privilege, expected, actual)
		}

		return nil
	}
}

func testAccRedshiftScopedGrantExec(t *testing.T, query string) {
	client := testAccProvider.Meta().(*Client)
	conn, err := client.Connect()
	if err != nil {
		t.Fatalf("couldn't start redshift connection: %s", err)
	}

	if _, err := conn.Exec(query); err != nil {
		t.Fatalf("couldn't run %q: %s", query, err)
	}
}

// testAccRedshiftScopedGrantExecIgnoreErrors runs cleanup statements and logs errors
// instead of failing. A "%s" in a statement is replaced with the quoted name of the
// provider database.
func testAccRedshiftScopedGrantExecIgnoreErrors(queries ...string) {
	meta := testAccProvider.Meta()
	if meta == nil {
		return
	}
	client := meta.(*Client)

	conn, err := client.Connect()
	if err != nil {
		log.Printf("[WARN] couldn't start redshift connection for cleanup: %s", err)
		return
	}

	for _, query := range queries {
		if strings.Contains(query, "%s") {
			query = fmt.Sprintf(query, pq.QuoteIdentifier(client.databaseName))
		}
		if _, err := conn.Exec(query); err != nil {
			log.Printf("[DEBUG] cleanup statement %q failed: %s", query, err)
		}
	}
}
