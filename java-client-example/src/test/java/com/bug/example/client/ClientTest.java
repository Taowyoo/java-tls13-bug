package com.bug.example.client;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import javax.net.ssl.SSLContext;

public class ClientTest {
    @BeforeEach
    public void setUp(TestInfo testInfo) throws Exception {
        // Reset the security providers before each test
        Security.removeProvider(Client.OPENSSL_PROVIDER_NAME);
        String displayName = testInfo.getDisplayName();
        System.out.println("Testing: " + displayName);
    }

    @Test
    public void testConnectWithOpenSSLProvider() throws Exception {
        // OpenSSLProvider from Conscrypt can handle certificate_authorities
        // extension with a empty list of authorities
        assertDoesNotThrow(() -> Client.connectWithOpenSSLProvider());
    }

    @Test
    public void testConnectWithDefaultProvider() throws Exception {
        // Java default security provider cannot handle certificate_authorities
        // extension with a empty list of authorities
        try {
            Client.connectWithDefaultProvider();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Java default security provider cannot handle certificate_authorities"
                    + " extension with a empty list of authorities", e);
        }

    }

    @Test
    public void testSetOpenSSLProviderAsDefault() throws Exception {
        // Call the method to set the default security provider
        Client.setOpenSSLProviderAsDefault();

        // Get the default SSL context and the name of its provider
        String defaultProviderName = SSLContext.getDefault().getProvider().getName();

        // Check if the default provider is set to OpenSSLProvider
        assertEquals(Client.OPENSSL_PROVIDER_NAME, defaultProviderName);
    }
}
