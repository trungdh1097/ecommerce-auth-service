package com.d10g.ecommerce_auth.application.role;

import com.d10g.ecommerce_auth.application.account.AccountPorts;
import com.d10g.ecommerce_auth.domain.account.Account;

import java.util.Optional;
import java.util.UUID;

public final class RoleService {
    private final RolePort adapter;
    private final AccountPorts accountAdapter;

    public RoleService(RolePort adapter, AccountPorts accountAdapter) {
        this.adapter = adapter;
        this.accountAdapter = accountAdapter;
    }

    public boolean hasRole(UUID userId, String roleName) {
        if (userId == null || roleName == null || roleName.isBlank()) return false;
        return adapter.hasRole(userId, roleName);
    }

    public Result changeRole(UUID userId, Integer roleId) {
        return adapter.inTransaction(() -> {
            if (userId == null) return Result.INVALID_USERID;
            if (roleId == null) return Result.INVALID_ROLE;

            Optional<RolePort.Role> role = adapter.findById(roleId);
            Optional<Account> account = accountAdapter.lockById(userId);

            if (account.isEmpty()) return Result.INVALID_USERID;

            if (role.isPresent()) {
                adapter.changeRole(userId, roleId);
                return Result.OK;
            } else {
                return Result.INVALID_ROLE;
            }
        });
    }


    public enum Result {OK, INVALID_ROLE, INVALID_USERID}
}
