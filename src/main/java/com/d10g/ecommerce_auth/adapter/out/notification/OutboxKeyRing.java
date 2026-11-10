package com.d10g.ecommerce_auth.adapter.out.notification;

import com.d10g.ecommerce_auth.security.crypto.OutboxCipher;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Outbox encryption keys are supplied outside the database and repository.
 */
public final class OutboxKeyRing {
    private final String activeKeyId;
    private final Map<String, OutboxCipher> ciphers;

    public OutboxKeyRing(String activeKeyId, Map<String, String> encodedKeys) {
        if (activeKeyId == null || activeKeyId.isBlank() || encodedKeys == null) {
            throw new IllegalArgumentException("Outbox active key and keys are required");
        }
        Map<String, OutboxCipher> result = new LinkedHashMap<>();
        encodedKeys.forEach((id, encoded) -> {
            if (id == null || id.isBlank() || encoded == null) throw new IllegalArgumentException("Invalid outbox key");
            result.put(id, new OutboxCipher(Base64.getDecoder().decode(encoded)));
        });
        if (!result.containsKey(activeKeyId)) throw new IllegalArgumentException("Active outbox key not found");
        this.activeKeyId = activeKeyId;
        this.ciphers = Map.copyOf(result);
    }

    public String activeKeyId() {
        return activeKeyId;
    }

    public OutboxCipher activeCipher() {
        return ciphers.get(activeKeyId);
    }

    public OutboxCipher cipher(String keyId) {
        return ciphers.get(keyId);
    }
}
