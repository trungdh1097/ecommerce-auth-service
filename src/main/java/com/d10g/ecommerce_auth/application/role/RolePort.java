package com.d10g.ecommerce_auth.application.role;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

public interface RolePort {
    <T> T inTransaction(Supplier<T> work);

    Optional<Role> findById(int roleId);

    boolean hasRole(UUID userId, String roleName);

    void changeRole(UUID userId, int roleId);

    record Role(int roleId, String name, String description) {
    }
}
