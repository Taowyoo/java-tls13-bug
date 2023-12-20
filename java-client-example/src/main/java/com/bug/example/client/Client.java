package com.bug.example.client;

import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.conscrypt.OpenSSLProvider;

public class Client {

    public static final String OPENSSL_PROVIDER_NAME = new OpenSSLProvider().getName();
    public static final String DEFAULT_PROVIDER_NAME = "SunJSSE";

    public static void connectWithOpenSSLProvider() throws Exception {
        setOpenSSLProviderAsDefault();
        connect(OPENSSL_PROVIDER_NAME);
    }

    public static void connectWithDefaultProvider() throws Exception {
        Security.removeProvider(OPENSSL_PROVIDER_NAME);
        connect(DEFAULT_PROVIDER_NAME);
    }

    public static void connect(String expectedProviderName) throws Exception {
        // Specify the host and port to connect to
        String host = "127.0.0.1";
        int port = 4443;

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("TLS");
        assert sc.getProvider().getName() == expectedProviderName;
        sc.init(null, trustAllCerts, new SecureRandom());

        // Create an SSLSocketFactory from the SSLContext
        SSLSocketFactory sslSocketFactory = sc.getSocketFactory();

        // Create an SSLSocket
        SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);

        // Start the handshake with the server
        sslSocket.startHandshake();
        SSLSession session = sslSocket.getSession();
        System.out.println("Cipher Suite: " + session.getCipherSuite());
        System.out.println("Protocol: " + session.getProtocol());
        System.out.println("Peer Host: " + session.getPeerHost());
        System.out.println("Peer Port: " + session.getPeerPort());

        sslSocket.close();
    }

    public static void setOpenSSLProviderAsDefault() throws Exception {
        OpenSSLProvider provider = new OpenSSLProvider();
        if (Security.getProvider(OPENSSL_PROVIDER_NAME) != null) {
            Security.removeProvider(OPENSSL_PROVIDER_NAME);
        }
        Security.insertProviderAt(provider, 1);
    }
}
