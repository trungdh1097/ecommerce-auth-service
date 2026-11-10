package com.d10g.ecommerce_auth.adapter.in.web;

import static org.junit.jupiter.api.Assertions.*;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ClientRegistryTest {
    private final ClientRegistry registry = new ClientRegistry(Map.of(
            "web", new ClientRegistry.Registration(Platform.WEB, "google-web", Set.of()),
            "android", new ClientRegistry.Registration(Platform.ANDROID, "google-app", Set.of())),
            Set.of("https://shop.example.test"));

    @Test void usesConfiguredPlatformAndExactOrigin() {
        assertEquals(Platform.WEB, registry.validateMutation("web", "https://shop.example.test", true).platform());
        assertThrows(IllegalArgumentException.class, () -> registry.validateMutation("web", "https://shop.example.test.evil", true));
        assertThrows(IllegalArgumentException.class, () -> registry.validateMutation("web", null, false));
        assertThrows(IllegalArgumentException.class, () -> registry.validateMutation("unknown", null, false));
    }
    @Test void nativeDoesNotAcceptBrowserCredentialsOrOrigin() {
        assertEquals(Platform.ANDROID, registry.validateMutation("android", null, false).platform());
        assertThrows(IllegalArgumentException.class, () -> registry.validateMutation("android", "https://shop.example.test", false));
        assertThrows(IllegalArgumentException.class, () -> registry.validateMutation("android", null, true));
    }
    @Test void rejectsInvalidOriginConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new ClientRegistry(Map.of("web", new ClientRegistry.Registration(Platform.WEB, "a", Set.of())), Set.of("https://*.example.com")));
    }
}
