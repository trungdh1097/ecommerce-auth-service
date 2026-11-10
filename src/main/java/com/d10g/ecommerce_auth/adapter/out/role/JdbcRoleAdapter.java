package com.d10g.ecommerce_auth.adapter.out.role;

import com.d10g.ecommerce_auth.application.role.RolePort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

public class JdbcRoleAdapter implements RolePort {
    private final JdbcTemplate db;
    private final TransactionTemplate transaction;

    public JdbcRoleAdapter(JdbcTemplate db, TransactionTemplate transaction) {
        this.db = db;
        this.transaction = transaction;
    }

    @Override
    public <T> T inTransaction(Supplier<T> work) {
        return transaction.execute(status -> work.get());
    }

    @Override
    public Optional<Role> findById(int roleId) {
        return db.query("select * from roles where id = ?", (rs, n) -> new Role(
                rs.getInt("id"),
                rs.getString("name"),
                rs.getString("description")
        ), roleId).stream().findFirst();
    }

    @Override
    public boolean hasRole(UUID userId, String roleName) {
        return Boolean.TRUE.equals(db.queryForObject("""
                select exists (
                    select 1 from account_roles ar
                    join roles r on r.id = ar.role_id
                    where ar.account_id = ? and r.name = ?
                )
                """, Boolean.class, userId, roleName));
    }

    @Override
    public void changeRole(UUID userId, int roleId) {
        db.update("update account_roles set role_id= ? where account_id = ?", roleId, userId);
    }
}
