package nl.xservices.plugins;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;

import android.util.Log;

public class SSLCertificateChecker extends CordovaPlugin {

    private static final String TAG = "SSLCertificateChecker";
    private static final String ACTION_CHECK_EVENT = "check";
    private static char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    @Override
    public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) throws JSONException {
        if (ACTION_CHECK_EVENT.equals(action)) {
            try {
                String serverURL = args.getString(0);
                String allowedFingerprint = args.getString(1);

                HttpsURLConnection conn = (HttpsURLConnection) new URL(serverURL).openConnection();
                conn.setConnectTimeout(5000);
                conn.connect();
                Certificate[] certificates = conn.getServerCertificates();

                String[] serverCertificateFingerprints = new String[certificates.length];
                String[] serverCertificateCommonNames = new String[certificates.length];

                MessageDigest md = MessageDigest.getInstance("SHA256");

                X509Certificate xcertificate;
                for (int i = 0; i < certificates.length; i++) {
                    md.update(certificates[i].getEncoded());
                    serverCertificateFingerprints[i] = dumpHex(md.digest());
                    md.reset();

                    xcertificate = (X509Certificate) certificates[i];
                    serverCertificateCommonNames[i] = getFieldValue("CN", xcertificate.getSubjectDN().getName());
                }

                serverURL = serverURL.startsWith("https://") ? serverURL.substring(("https://").length()) : serverURL;
                serverURL = serverURL.substring(0, serverURL.indexOf("/Motor"));
                
                boolean isFingerprintOK = false;
                boolean isCommonNameOK = false;
                for (int i = 0; i < certificates.length; i++) {
                    if (serverCertificateFingerprints[i].equals(allowedFingerprint)) {
                        isFingerprintOK = true;
                    }
                    if (serverCertificateCommonNames[i].contains(serverURL)) {
                        isCommonNameOK = true;
                    }
                }

                if (isFingerprintOK && isCommonNameOK) {
                    callbackContext.success("CONNECTION_SECURE");
                } else {
                    callbackContext.error("CONNECTION_NOT_SECURE");
                }
            } catch (Exception e) {
                callbackContext.error("CONNECTION_FAILED");
            }
            return true;
        }
        return false;
    }

    public String getFieldValue(String field, String data) {
        field = field + "=";
        if (!data.contains(field)) {
            return null;
        }

        String value = data.substring(data.indexOf(field) + field.length());
        if (value.contains("=")) {
            value = value.substring(0, value.indexOf("=") - (value.charAt(value.indexOf("=") - 3) != ' ' ? 3 : 4));
        }

        return value;
    }

    private static String dumpHex(byte[] data) {
        final int n = data.length;
        final StringBuilder sb = new StringBuilder(n * 3 - 1);
        for (int i = 0; i < n; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(HEX_CHARS[(data[i] >> 4) & 0x0F]);
            sb.append(HEX_CHARS[data[i] & 0x0F]);
        }
        return sb.toString();
    }
}
