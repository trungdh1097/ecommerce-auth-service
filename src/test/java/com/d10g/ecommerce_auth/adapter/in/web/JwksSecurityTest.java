package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.configuration.SecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(JwksController.class)
@Import(SecurityConfiguration.class)
class JwksSecurityTest {
    @Autowired MockMvc mvc;
    @Test void jwksWithoutConfiguredKeysReturnsUnavailable() throws Exception {
        mvc.perform(get("/.well-known/jwks.json")).andExpect(status().isServiceUnavailable())
                .andExpect(header().string("Cache-Control", "no-store"));
    }
    @Test void otherRoutesRemainDenied() throws Exception {
        mvc.perform(get("/api/v1/auth/sessions")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/login")).andExpect(status().isServiceUnavailable());
    }
}
