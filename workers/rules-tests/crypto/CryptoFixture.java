// Test fixture for workers/rules/pathos-crypto.yml (Java). Not compiled.
package fixture;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.conn.ssl.NoopHostnameVerifier;

public class CryptoFixture {
    byte[] hashing(byte[] data) throws Exception {
        // ruleid: pathos.crypto.java.weak-hash
        String a = DigestUtils.md5Hex(data);
        // ruleid: pathos.crypto.java.weak-hash
        MessageDigest b = MessageDigest.getInstance("MD4");
        // ok: pathos.crypto.java.weak-hash
        MessageDigest c = MessageDigest.getInstance("SHA-256");
        return c.digest(data);
    }

    void ciphers(SecretKeySpec key) throws Exception {
        // ruleid: pathos.crypto.java.weak-cipher
        Cipher des = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        // ruleid: pathos.crypto.java.weak-cipher
        Cipher rc4 = Cipher.getInstance("RC4");
        // ruleid: pathos.crypto.java.ecb-mode
        Cipher aes = Cipher.getInstance("AES");
        // ruleid: pathos.crypto.java.ecb-mode
        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ok: pathos.crypto.java.ecb-mode, pathos.crypto.java.weak-cipher
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        // ruleid: pathos.crypto.java.static-iv
        IvParameterSpec iv = new IvParameterSpec("0000000000000000".getBytes());
        // ruleid: pathos.crypto.java.static-iv
        GCMParameterSpec spec = new GCMParameterSpec(128, new byte[12]);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        // ok: pathos.crypto.java.static-iv
        GCMParameterSpec spec2 = new GCMParameterSpec(128, nonce);
        gcm.init(Cipher.ENCRYPT_MODE, key, spec2);
    }

    void keys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        // ruleid: pathos.crypto.java.small-rsa-key
        gen.initialize(1024);
        KeyPairGenerator gen2 = KeyPairGenerator.getInstance("RSA");
        // ok: pathos.crypto.java.small-rsa-key
        gen2.initialize(3072);
    }

    String tokens() {
        // ruleid: pathos.crypto.java.insecure-random-secret
        String resetToken = Long.toHexString(new Random().nextLong());
        Random rnd = new Random();
        // ruleid: pathos.crypto.java.insecure-random-secret
        int otpCode = rnd.nextInt(1000000);
        // ok: pathos.crypto.java.insecure-random-secret
        int jitter = rnd.nextInt(100);
        byte[] salt = new byte[16];
        // ok: pathos.crypto.java.insecure-random-secret
        new SecureRandom().nextBytes(salt);
        return resetToken + otpCode + jitter;
    }

    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        // ruleid: pathos.crypto.java.tls-verification-disabled
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    static class AllHosts implements HostnameVerifier {
        // ruleid: pathos.crypto.java.tls-verification-disabled
        public boolean verify(String hostname, SSLSession session) { return true; }
    }

    void tls() throws Exception {
        // ruleid: pathos.crypto.java.tls-verification-disabled
        HostnameVerifier v = NoopHostnameVerifier.INSTANCE;
        // ruleid: pathos.crypto.java.tls-verification-disabled
        SSLContext old = SSLContext.getInstance("TLSv1");
        // ok: pathos.crypto.java.tls-verification-disabled
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
    }

    void hardcoded() {
        // ruleid: pathos.crypto.java.hardcoded-key
        SecretKeySpec k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
        // ok: pathos.crypto.java.hardcoded-key
        SecretKeySpec k2 = new SecretKeySpec(System.getenv("AES_KEY").getBytes(), "AES");
    }
}
