package com.d10g.ecommerce_auth.configuration;

import com.d10g.ecommerce_auth.adapter.out.session.RsaAccessTokens;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Keys are supplied through external configuration; no default credentials or keys are generated.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(JwtKeyConfiguration.Properties.class)
public class JwtKeyConfiguration {
    private static byte[] pem(String value, String label) {
        if (value == null) throw new IllegalArgumentException("Missing " + label);
        String normalized = value.replace("-----BEGIN " + label + "-----", "")
                .replace("-----END " + label + "-----", "").replaceAll("\\s+", "");
        return Base64.getDecoder().decode(normalized);
    }

    @Bean
    @ConditionalOnProperty(prefix = "auth.jwt", name = {"issuer", "audience", "active-key-id", "private-key-pem"})
    RsaAccessTokens rsaAccessTokens(Properties properties) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(pem(properties.getPrivateKeyPem(), "PRIVATE KEY")));
            Map<String, RSAPublicKey> keys = new HashMap<>();
            for (var entry : properties.getPublicKeys().entrySet()) {
                keys.put(entry.getKey(), (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(pem(entry.getValue(), "PUBLIC KEY"))));
            }
            return new RsaAccessTokens(properties.getIssuer(), properties.getAudience(), properties.getActiveKeyId(), privateKey, keys, Clock.systemUTC());
        } catch (Exception ex) {
            throw new IllegalStateException("Invalid JWT key configuration", ex);
        }
    }

    @ConfigurationProperties(prefix = "auth.jwt")
    public static class Properties {
        private String issuer;
        private String audience;
        private String activeKeyId;
        private String privateKeyPem;
        private Map<String, String> publicKeys = new HashMap<>();

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getActiveKeyId() {
            return activeKeyId;
        }

        public void setActiveKeyId(String activeKeyId) {
            this.activeKeyId = activeKeyId;
        }

        public String getPrivateKeyPem() {
            return privateKeyPem;
        }

        public void setPrivateKeyPem(String privateKeyPem) {
            this.privateKeyPem = privateKeyPem;
        }

        public Map<String, String> getPublicKeys() {
            return publicKeys;
        }

        public void setPublicKeys(Map<String, String> publicKeys) {
            this.publicKeys = publicKeys;
        }
    }
}
