package org.pathos.testapp;

import android.app.Activity;
import android.os.Bundle;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.webkit.WebView;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

// Deliberately insecure code for the PATHOS worker-mobile fixtures.
public class MainActivity extends Activity {
    // Test values, not real credentials.
    private static final String API_KEY = "pathosTestApiKeyValue0123456789abcd";
    private static final String AUTH_HEADER = "bearer pathos-test-session-value";
    private static final String LOGIN_URL = "http://api.pathos-test.invalid/v1/login";
    private static final String BACKEND_IP = "10.20.30.40";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView web = new WebView(this);
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setAllowFileAccess(true);
        web.addJavascriptInterface(new Bridge(), "bridge");
        web.loadUrl(LOGIN_URL);
        setContentView(web);
        String password = getIntent().getStringExtra("password");
        Log.d("PathosTest", "login password=" + password);
        int token = new Random().nextInt();
        Log.i("PathosTest", "session token " + token);
    }

    void leakDeviceId() throws Exception {
        TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
        String id = tm.getDeviceId();
        HttpURLConnection c = (HttpURLConnection) new URL(LOGIN_URL + "?device=" + id).openConnection();
        c.setDoOutput(true);
        OutputStream out = c.getOutputStream();
        out.write(id.getBytes());
        out.close();
        SmsManager.getDefault().sendTextMessage("+15550100", null, "device " + id, null, null);
    }

    byte[] weakCrypto(byte[] data) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        md5.update(data);
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("0123456789abcdef".getBytes(), "AES"));
        return c.doFinal(md5.digest());
    }

    void runShell(String cmd) throws Exception {
        Runtime.getRuntime().exec("sh -c " + cmd);
    }

    static class Bridge {
        @android.webkit.JavascriptInterface
        public String secret() {
            return API_KEY + AUTH_HEADER + BACKEND_IP;
        }
    }
}
