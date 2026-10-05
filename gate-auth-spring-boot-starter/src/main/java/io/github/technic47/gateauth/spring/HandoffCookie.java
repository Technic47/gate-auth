package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.Base64Url;
import io.github.technic47.gateauth.core.Json;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * State the app keeps while the browser is at the gate (spec §6.4): {@code state}, {@code nonce}, return path,
 * expiry and whether this is a silent re-check. Stored client-side, HMAC-SHA256 signed with {@code local-secret}.
 */
record HandoffCookie(String state, String nonce, String returnPath, long expiresAt, boolean recheck) {

    static final long LIFETIME_SECONDS = 600;

    String encode(String secret) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("s", state);
        m.put("n", nonce);
        m.put("r", returnPath);
        m.put("e", expiresAt);
        m.put("c", recheck);
        String body = Base64Url.encode(Json.write(m));
        return body + "." + Base64Url.encode(hmac(secret, body));
    }

    static Optional<HandoffCookie> decode(String value, String secret, long now) {
        if (value == null || value.length() > 4096) {
            return Optional.empty();
        }
        int dot = value.indexOf('.');
        if (dot < 0) {
            return Optional.empty();
        }
        String body = value.substring(0, dot);
        try {
            byte[] mac = Base64Url.decode(value.substring(dot + 1));
            if (!MessageDigest.isEqual(mac, hmac(secret, body))) {
                return Optional.empty();
            }
            Map<String, Object> m = Json.parseObject(Base64Url.decodeToString(body));
            HandoffCookie c = new HandoffCookie((String) m.get("s"), (String) m.get("n"), (String) m.get("r"),
                    (Long) m.get("e"), Boolean.TRUE.equals(m.get("c")));
            if (c.state() == null || c.nonce() == null || c.expiresAt() < now) {
                return Optional.empty();
            }
            return Optional.of(c);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private static byte[] hmac(String secret, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.US_ASCII));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
