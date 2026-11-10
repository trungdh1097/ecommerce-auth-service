package com.d10g.ecommerce_auth.adapter.in.web;

import static org.junit.jupiter.api.Assertions.*;
import com.d10g.ecommerce_auth.application.session.SessionManagementService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class SessionManagementControllerTest {
    @Test void returnsRecognizedBrowserAndOperatingSystem() {
        UUID user=UUID.randomUUID(), session=UUID.randomUUID();
        var now=Instant.now();
        var store=new SessionManagementService.Store() {
            public <T>T inTransaction(Supplier<T> work){return work.get();}
            public SessionManagementService.Profile findProfile(UUID id){return null;}
            public List<SessionManagementService.SessionItem> list(UUID id,UUID current,SessionManagementService.Cursor cursor,int limit){
                return List.of(new SessionManagementService.SessionItem(session,"WEB","Laptop",
                        "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36 Edg/120.0",
                        "192.0.2.x",now,now,now.plusSeconds(100),true));
            }
            public SessionManagementService.RevokeResult revoke(UUID id,UUID sid){return SessionManagementService.RevokeResult.REVOKED;}
            public void revokeAll(UUID id){}
        };
        var result=new SessionManagementController(new SessionManagementService(store)).list(new AuthPrincipal(user,session),null,null);
        var item=result.getBody().sessions().get(0);
        assertEquals("Edge",item.browser());
        assertEquals("Windows",item.operatingSystem());
        assertTrue(item.current());
    }
}
