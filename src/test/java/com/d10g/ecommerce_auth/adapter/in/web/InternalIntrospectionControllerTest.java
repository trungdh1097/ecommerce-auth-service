package com.d10g.ecommerce_auth.adapter.in.web;

import static com.d10g.ecommerce_auth.application.session.SessionPorts.*;
import static org.junit.jupiter.api.Assertions.*;

import com.d10g.ecommerce_auth.adapter.out.session.RsaAccessTokens;
import com.d10g.ecommerce_auth.application.session.SessionService;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;

/** Simulates the servlet container's certificate attribute; does not test a TLS handshake. */
class InternalIntrospectionControllerTest {
    private static final Instant NOW=Instant.parse("2026-01-01T00:00:00Z");
    private static final UUID USER=UUID.randomUUID(), SESSION=UUID.randomUUID();
    private static RsaAccessTokens tokens;
    private static String access;
    private static final byte[] CERT_BYTES = {1,2,3,4};
    private static final String CERT_ATTRIBUTE="jakarta.servlet.request.X509Certificate";
    private final FakeStore store = new FakeStore();

    @BeforeAll static void setup() throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        var key=generator.generateKeyPair();
        tokens=new RsaAccessTokens("issuer","api","key",(RSAPrivateKey)key.getPrivate(),
                Map.of("key",(RSAPublicKey)key.getPublic()),Clock.fixed(NOW, ZoneOffset.UTC));
        access=tokens.sign(session(true),NOW,NOW.plusSeconds(300));
    }
    private static ActiveSession session(boolean active) {
        return new ActiveSession(USER,SESSION,"app",Platform.ANDROID,1,NOW.minusSeconds(5),"pwd otp",
                NOW.plusSeconds(600),NOW,active,true,1);
    }
    private InternalIntrospectionController controller() throws Exception {
        String fingerprint=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(CERT_BYTES));
        Transaction tx=new Transaction(){ public <T>T execute(Supplier<T> work){ return work.get(); }};
        Secrets secrets=new Secrets(){ public String newRefreshToken(){ return "unused"; } public byte[] hash(String s){ return new byte[0]; }};
        var service=new SessionService(tx,store,secrets,tokens,Clock.fixed(NOW,ZoneOffset.UTC));
        return new InternalIntrospectionController(tokens,service,fingerprint);
    }
    private static MockHttpServletRequest request(boolean secure,X509Certificate cert) {
        var request=new MockHttpServletRequest(); request.setSecure(secure);
        if(cert!=null) request.setAttribute(CERT_ATTRIBUTE,new X509Certificate[]{cert});
        return request;
    }
    @Test void rejectsMissingUnpinnedExpiredAndInsecureCertificates() throws Exception {
        var controller=controller();
        for(var request:java.util.List.of(request(false,new StubCert(CERT_BYTES,false)),request(true,null),
                request(true,new StubCert(new byte[]{9},false)),request(true,new StubCert(CERT_BYTES,true)))) {
            var error=assertThrows(ResponseStatusException.class,()->controller.introspect(request,new InternalIntrospectionController.Request(access)));
            assertEquals(HttpStatus.UNAUTHORIZED,error.getStatusCode());
        }
        assertFalse(store.queried);
    }
    @Test void validCertificateAndActiveSessionReturnIdentity() throws Exception {
        store.active=session(true);
        var response=controller().introspect(request(true,new StubCert(CERT_BYTES,false)),new InternalIntrospectionController.Request(access));
        assertTrue(response.getBody().active()); assertEquals(USER,response.getBody().user_id()); assertEquals(SESSION,response.getBody().session_id());
        assertEquals(NOW.plusSeconds(300),response.getBody().expires_at());
        assertTrue(response.getHeaders().getCacheControl().contains("no-store"));
    }
    @Test void invalidTokenAndRevokedSessionAreInactive() throws Exception {
        var controller=controller(); var request=request(true,new StubCert(CERT_BYTES,false));
        assertFalse(controller.introspect(request,new InternalIntrospectionController.Request("invalid")).getBody().active());
        assertFalse(store.queried);
        store.active=session(false);
        assertFalse(controller.introspect(request,new InternalIntrospectionController.Request(access)).getBody().active());
        assertTrue(store.queried);
    }
    @Test void databaseFailureIsUnavailableRatherThanInactive() throws Exception {
        store.fail=true;
        var error=assertThrows(ResponseStatusException.class,()->controller().introspect(request(true,new StubCert(CERT_BYTES,false)),new InternalIntrospectionController.Request(access)));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE,error.getStatusCode());
    }
    private static final class FakeStore implements Store {
        boolean queried,fail; ActiveSession active;
        public LockedCredential lockCredential(byte[] h,Client c){throw new UnsupportedOperationException();}
        public void rotate(LockedCredential c,UUID id,byte[] h,Instant now){throw new UnsupportedOperationException();}
        public void revoke(LockedCredential c,Instant now,String reason){throw new UnsupportedOperationException();}
        public ActiveSession findActive(UUID user,UUID session){queried=true; if(fail) throw new DataAccessResourceFailureException("test"); return active;}
    }
    @SuppressWarnings("deprecation")
    private static final class StubCert extends X509Certificate {
        private final byte[] bytes; private final boolean expired;
        StubCert(byte[] bytes,boolean expired){this.bytes=bytes;this.expired=expired;}
        public void checkValidity() throws CertificateExpiredException { if(expired)throw new CertificateExpiredException(); }
        public void checkValidity(Date date) throws CertificateExpiredException {checkValidity();}
        public byte[] getEncoded(){return bytes.clone();} public void verify(PublicKey key){} public void verify(PublicKey key,String provider){}
        public String toString(){return "test certificate";} public PublicKey getPublicKey(){return null;}
        public int getVersion(){return 3;} public BigInteger getSerialNumber(){return BigInteger.ONE;}
        public Principal getIssuerDN(){return null;} public Principal getSubjectDN(){return null;}
        public Date getNotBefore(){return new Date(0);} public Date getNotAfter(){return new Date(Long.MAX_VALUE);}
        public byte[] getTBSCertificate(){return bytes.clone();} public byte[] getSignature(){return new byte[0];}
        public String getSigAlgName(){return "none";} public String getSigAlgOID(){return "0.0";} public byte[] getSigAlgParams(){return null;}
        public boolean[] getIssuerUniqueID(){return null;} public boolean[] getSubjectUniqueID(){return null;}
        public boolean[] getKeyUsage(){return null;} public int getBasicConstraints(){return -1;}
        public Set<String> getCriticalExtensionOIDs(){return null;} public Set<String> getNonCriticalExtensionOIDs(){return null;}
        public byte[] getExtensionValue(String oid){return null;} public boolean hasUnsupportedCriticalExtension(){return false;}
    }
}
