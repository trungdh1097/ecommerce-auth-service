package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.application.role.RoleService;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/role")
@ConditionalOnProperty(prefix = "auth.runtime", name = "enabled", havingValue = "true")
public class RoleController {
    private final RoleService service;

    public RoleController(RoleService service) {
        this.service = service;
    }

    public record ChangeRoleRequest(UUID accountId, Integer roleId) {
    }

    private static ResponseEntity<Void> noContent() {
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    @PostMapping("/change")
    public ResponseEntity<?> changeRole(@RequestBody @NonNull ChangeRoleRequest request) {
        var result = service.changeRole(request.accountId, request.roleId);

        if (result == RoleService.Result.INVALID_USERID) {
            throw new ApiProblemException(400, "USER_ID_INVALID");
        }

        if (result == RoleService.Result.INVALID_ROLE) {
            throw new ApiProblemException(400, "ROLE_INVALID");
        }

        return noContent();
    }
}
