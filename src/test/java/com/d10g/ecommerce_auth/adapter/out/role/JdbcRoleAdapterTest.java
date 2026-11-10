package com.d10g.ecommerce_auth.adapter.out.role;

import com.d10g.ecommerce_auth.application.role.RolePort.Role;
import java.lang.reflect.Proxy;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.junit.jupiter.api.Assertions.*;

class JdbcRoleAdapterTest {
    private final FakeJdbc db = new FakeJdbc();
    private final RecordingTransactions transactions = new RecordingTransactions();
    private final JdbcRoleAdapter adapter = new JdbcRoleAdapter(db, new TransactionTemplate(transactions));

    @Test void findByIdBindsIdentifierAndMapsRole() {
        assertEquals(new Role(7, "ADMIN", "Administrator"), adapter.findById(7).orElseThrow());
        assertTrue(db.sql.contains("where id = ?"));
        assertArrayEquals(new Object[]{7}, db.args);
    }

    @Test void findByIdReturnsEmptyForUnknownRole() {
        db.empty = true;
        assertTrue(adapter.findById(99).isEmpty());
        assertArrayEquals(new Object[]{99}, db.args);
    }

    @Test void transactionExecutesWorkAndCommitsItsResult() {
        Object result = new Object();
        assertSame(result, adapter.inTransaction(() -> {
            assertTrue(TransactionSynchronizationManager.isActualTransactionActive());
            return result;
        }));
        assertEquals(1, transactions.commits);
        assertEquals(0, transactions.rollbacks);
    }

    @Test void transactionRollsBackAndPropagatesFailure() {
        var failure = new IllegalStateException("database failure");
        assertSame(failure, assertThrows(IllegalStateException.class, () -> adapter.inTransaction(() -> {
            throw failure;
        })));
        assertEquals(0, transactions.commits);
        assertEquals(1, transactions.rollbacks);
    }

    private static class FakeJdbc extends JdbcTemplate {
        String sql;
        Object[] args;
        boolean empty;

        @Override public <T> List<T> query(String sql, RowMapper<T> mapper, Object... args) {
            this.sql = sql;
            this.args = args;
            if (empty) return List.of();
            ResultSet row = (ResultSet) Proxy.newProxyInstance(getClass().getClassLoader(),
                    new Class<?>[]{ResultSet.class}, (proxy, method, values) -> switch (method.getName()) {
                        case "getInt" -> 7;
                        case "getString" -> "name".equals(values[0]) ? "ADMIN" : "Administrator";
                        default -> throw new UnsupportedOperationException(method.getName());
                    });
            try {
                return List.of(mapper.mapRow(row, 0));
            } catch (SQLException e) {
                throw new AssertionError(e);
            }
        }
    }

    private static class RecordingTransactions extends AbstractPlatformTransactionManager {
        int commits;
        int rollbacks;

        @Override protected Object doGetTransaction() { return new Object(); }
        @Override protected void doBegin(Object transaction, TransactionDefinition definition) { }
        @Override protected void doCommit(DefaultTransactionStatus status) { commits++; }
        @Override protected void doRollback(DefaultTransactionStatus status) { rollbacks++; }
    }
}
