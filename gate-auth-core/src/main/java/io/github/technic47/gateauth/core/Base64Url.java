package io.github.technic47.gateauth.core;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * base64url without padding, as used by JWS (RFC 7515 §2).
 */
public final class Base64Url {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private Base64Url() {
    }

    /**
     * Encodes bytes.
     *
     * @param bytes data to encode
     * @return base64url text without padding
     */
    public static String encode(byte[] bytes) {
        return ENCODER.encodeToString(bytes);
    }

    /**
     * Encodes the UTF-8 bytes of a string.
     *
     * @param text text to encode
     * @return base64url text without padding
     */
    public static String encode(String text) {
        return encode(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decodes strictly: padding and characters outside the base64url alphabet are rejected.
     *
     * @param text base64url text without padding
     * @return decoded bytes
     * @throws IllegalArgumentException if the text is not valid base64url
     */
    public static byte[] decode(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) {
                throw new IllegalArgumentException("Not base64url");
            }
        }
        return DECODER.decode(text);
    }

    /**
     * Decodes to a UTF-8 string.
     *
     * @param text base64url text without padding
     * @return decoded text
     * @throws IllegalArgumentException if the text is not valid base64url
     */
    public static String decodeToString(String text) {
        return new String(decode(text), StandardCharsets.UTF_8);
    }
}
