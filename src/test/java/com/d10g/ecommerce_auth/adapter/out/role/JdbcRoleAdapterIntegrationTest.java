package com.d10g.ecommerce_auth.adapter.out.role;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

/** Verifies authorization against real PostgreSQL role assignments in an isolated schema. */
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DB_URL", matches = ".+")
class JdbcRoleAdapterIntegrationTest {
    private static final UUID ADMIN = UUID.randomUUID();
    private static final UUID ORDINARY = UUID.randomUUID();
    private static final UUID UNASSIGNED = UUID.randomUUID();
    private static JdbcTemplate admin, db;
    private static JdbcRoleAdapter adapter;
    private static String schema;

    @BeforeAll static void setup() {
        String url = System.getenv("AUTH_TEST_DB_URL");
        String user = System.getenv().getOrDefault("AUTH_TEST_DB_USER", "postgres");
        String password = System.getenv().getOrDefault("AUTH_TEST_DB_PASSWORD", "");
        admin = new JdbcTemplate(new DriverManagerDataSource(url, user, password));
        schema = "auth_role_" + UUID.randomUUID().toString().replace("-", "");
        admin.execute("create schema " + schema);
        var ds = new DriverManagerDataSource(url + (url.contains("?") ? "&" : "?")
                + "currentSchema=" + schema, user, password);
        db = new JdbcTemplate(ds);
        db.execute("create table roles (id int primary key, name text not null)");
        db.execute("""
                create table account_roles (
                    account_id uuid not null,
                    role_id int not null references roles(id),
                    primary key (account_id, role_id)
                )
                """);
        adapter = new JdbcRoleAdapter(db, new TransactionTemplate(new DataSourceTransactionManager(ds)));
    }

    @AfterAll static void cleanup() {
        if (admin != null && schema != null) admin.execute("drop schema if exists " + schema + " cascade");
    }

    @BeforeEach void seed() {
        db.execute("truncate account_roles, roles");
        // ADMIN deliberately has an arbitrary ID: authorization must resolve the role name.
        db.update("insert into roles(id, name) values (7, 'ADMIN'), (2, 'USER')");
        db.update("insert into account_roles(account_id, role_id) values (?, 7), (?, 2)", ADMIN, ORDINARY);
    }

    @Test void adminPermissionBelongsOnlyToTheAssignedUserAndNamedRole() {
        assertTrue(adapter.hasRole(ADMIN, "ADMIN"));
        assertFalse(adapter.hasRole(ADMIN, "USER"));
        assertFalse(adapter.hasRole(ORDINARY, "ADMIN"));
        assertTrue(adapter.hasRole(ORDINARY, "USER"));
    }

    @Test void unassignedUserAndUnknownRoleAreDenied() {
        assertFalse(adapter.hasRole(UNASSIGNED, "ADMIN"));
        assertFalse(adapter.hasRole(ADMIN, "ROLE_DOES_NOT_EXIST"));
    }

    @Test void revokedAdminAssignmentIsObservedOnTheNextLookup() {
        assertTrue(adapter.hasRole(ADMIN, "ADMIN"));
        db.update("delete from account_roles where account_id = ? and role_id = 7", ADMIN);
        assertFalse(adapter.hasRole(ADMIN, "ADMIN"));
        db.update("insert into account_roles(account_id, role_id) values (?, 7)", ADMIN);
        assertTrue(adapter.hasRole(ADMIN, "ADMIN"));
    }
}
