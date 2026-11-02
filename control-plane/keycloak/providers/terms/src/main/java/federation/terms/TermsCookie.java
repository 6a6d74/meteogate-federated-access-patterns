package federation.terms;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The "remember my agreement" cookie: {@code <version>.<expiry>.<signature>}.
 *
 * <p>The signature is HMAC-SHA256 over the user's ID, the terms version and the expiry,
 * so a cookie counts only for the person it was set for (a shared browser asks the next
 * person), only for the current terms, and can't be forged or extended. It holds no
 * personal data: the user's ID is signed, not stored.
 */
final class TermsCookie {
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private TermsCookie() {}

    static String issue(String secret, String userId, String version, long expiresEpochSeconds) {
        String v = B64.encodeToString(version.getBytes(StandardCharsets.UTF_8));
        return v + "." + expiresEpochSeconds + "." + sign(secret, userId, version, expiresEpochSeconds);
    }

    static boolean valid(String secret, String cookie, String userId, String version, long nowEpochSeconds) {
        if (cookie == null || secret == null) {
            return false;
        }
        String[] parts = cookie.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        String cookieVersion;
        long expires;
        try {
            cookieVersion = new String(B64D.decode(parts[0]), StandardCharsets.UTF_8);
            expires = Long.parseLong(parts[1]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (!cookieVersion.equals(version) || expires <= nowEpochSeconds) {
            return false;
        }
        byte[] expected = sign(secret, userId, version, expires).getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expected, parts[2].getBytes(StandardCharsets.US_ASCII));
    }

    private static String sign(String secret, String userId, String version, long expires) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(
                    (userId + "\n" + version + "\n" + expires).getBytes(StandardCharsets.UTF_8));
            return B64.encodeToString(digest);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
