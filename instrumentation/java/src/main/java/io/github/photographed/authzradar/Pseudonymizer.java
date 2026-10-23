package io.github.photographed.authzradar;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Keyed pseudonyms (HMAC-SHA256) for identifiers sent to New Relic.
 *
 * <p>A plain hash is not enough: identifiers with a small value space (sequential user IDs,
 * IPv4 addresses) can be brute-forced back. Without a key nothing is sent.
 */
public class Pseudonymizer {

    private static final String ALGORITHM = "HmacSHA256";
    private final SecretKeySpec key;

    public Pseudonymizer(String secret) {
        this.key = (secret == null || secret.isBlank())
                ? null
                : new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    public boolean enabled() {
        return key != null;
    }

    /** {@code u_} + 16 hex chars, or {@code null} when no key is configured. */
    public String user(String rawUserId) {
        return pseudonym("u_", rawUserId, 8);
    }

    /** {@code k_} + 8 hex chars, or {@code null} when no key is configured. */
    public String apiKey(String rawApiKey) {
        return pseudonym("k_", rawApiKey, 4);
    }

    private String pseudonym(String prefix, String raw, int bytes) {
        if (key == null || raw == null || raw.isEmpty()) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(key);
            byte[] digest = mac.doFinal(raw.getBytes(StandardCharsets.UTF_8));
            return prefix + HexFormat.of().formatHex(digest, 0, bytes);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }
}
