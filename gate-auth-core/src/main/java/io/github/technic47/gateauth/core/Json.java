package io.github.technic47.gateauth.core;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal strict JSON reader/writer, enough for token headers, claims and JWKs.
 *
 * Keeps gate-auth-core free of dependencies (the apps use different Jackson majors).
 * Parsed values: {@code Map<String,Object>} (insertion order), {@code List<Object>}, {@code String},
 * {@code Long} (integers that fit) or {@code BigDecimal}, {@code Boolean}, {@code null}.
 */
public final class Json {

    private static final int MAX_DEPTH = 32;

    private final String src;
    private int pos;

    private Json(String src) {
        this.src = src;
    }

    /**
     * Parses any JSON value.
     *
     * @param text JSON text
     * @return a {@code Map}, {@code List}, {@code String}, {@code Long}, {@code BigDecimal}, {@code Boolean} or {@code null}
     * @throws IllegalArgumentException on invalid JSON, duplicate member names, nesting deeper than 32 or trailing data
     */
    public static Object parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("JSON text is null");
        }
        Json p = new Json(text);
        p.skipWs();
        Object value = p.readValue(0);
        p.skipWs();
        if (p.pos != text.length()) {
            throw p.error("trailing data");
        }
        return value;
    }

    /**
     * Parses JSON that must be an object.
     *
     * @param text JSON text
     * @return the object, members in document order
     * @throws IllegalArgumentException on invalid JSON or if the value is not an object
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object value = parse(text);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("JSON value is not an object");
        }
        return (Map<String, Object>) value;
    }

    /**
     * Writes a value as compact JSON. {@code <}, {@code >} and {@code &} are escaped, so the output is safe to
     * embed in HTML.
     *
     * @param value {@code Map}, {@code Collection}, {@code String}, {@code Integer}, {@code Long}, {@code BigDecimal},
     *              {@code Boolean} or {@code null}, nested freely
     * @return JSON text
     * @throws IllegalArgumentException for other value types
     */
    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    // ---------------------------------------------------------------- reading

    private Object readValue(int depth) {
        if (depth > MAX_DEPTH) {
            throw error("nesting too deep");
        }
        if (pos >= src.length()) {
            throw error("unexpected end");
        }
        char c = src.charAt(pos);
        return switch (c) {
            case '{' -> readObject(depth);
            case '[' -> readArray(depth);
            case '"' -> readString();
            case 't' -> readLiteral("true", Boolean.TRUE);
            case 'f' -> readLiteral("false", Boolean.FALSE);
            case 'n' -> readLiteral("null", null);
            default -> {
                if (c == '-' || (c >= '0' && c <= '9')) {
                    yield readNumber();
                }
                throw error("unexpected character '" + c + "'");
            }
        };
    }

    private Map<String, Object> readObject(int depth) {
        Map<String, Object> map = new LinkedHashMap<>();
        pos++; // {
        skipWs();
        if (peek() == '}') {
            pos++;
            return map;
        }
        while (true) {
            skipWs();
            if (peek() != '"') {
                throw error("expected member name");
            }
            String key = readString();
            skipWs();
            expect(':');
            skipWs();
            Object value = readValue(depth + 1);
            if (map.containsKey(key)) {
                throw error("duplicate member '" + key + "'");
            }
            map.put(key, value);
            skipWs();
            char c = next();
            if (c == '}') {
                return map;
            }
            if (c != ',') {
                throw error("expected ',' or '}'");
            }
        }
    }

    private List<Object> readArray(int depth) {
        List<Object> list = new ArrayList<>();
        pos++; // [
        skipWs();
        if (peek() == ']') {
            pos++;
            return list;
        }
        while (true) {
            skipWs();
            list.add(readValue(depth + 1));
            skipWs();
            char c = next();
            if (c == ']') {
                return list;
            }
            if (c != ',') {
                throw error("expected ',' or ']'");
            }
        }
    }

    private String readString() {
        pos++; // opening quote
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= src.length()) {
                throw error("unterminated string");
            }
            char c = src.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c < 0x20) {
                throw error("control character in string");
            }
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            char e = next();
            switch (e) {
                case '"' -> sb.append('"');
                case '\\' -> sb.append('\\');
                case '/' -> sb.append('/');
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    if (pos + 4 > src.length()) {
                        throw error("bad unicode escape");
                    }
                    try {
                        sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                    } catch (NumberFormatException ex) {
                        throw error("bad unicode escape");
                    }
                    pos += 4;
                }
                default -> throw error("bad escape '\\" + e + "'");
            }
        }
    }

    private Object readNumber() {
        int start = pos;
        if (peek() == '-') {
            pos++;
        }
        boolean integral = true;
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c >= '0' && c <= '9') {
                pos++;
            } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                integral = false;
                pos++;
            } else {
                break;
            }
        }
        String text = src.substring(start, pos);
        try {
            if (integral && text.length() <= 18) {
                return Long.parseLong(text);
            }
            return new BigDecimal(text);
        } catch (NumberFormatException ex) {
            throw error("bad number '" + text + "'");
        }
    }

    private Object readLiteral(String literal, Object value) {
        if (!src.startsWith(literal, pos)) {
            throw error("bad literal");
        }
        pos += literal.length();
        return value;
    }

    private void skipWs() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        if (pos >= src.length()) {
            throw error("unexpected end");
        }
        return src.charAt(pos);
    }

    private char next() {
        char c = peek();
        pos++;
        return c;
    }

    private void expect(char c) {
        if (next() != c) {
            throw error("expected '" + c + "'");
        }
    }

    private IllegalArgumentException error(String message) {
        return new IllegalArgumentException("Invalid JSON at " + pos + ": " + message);
    }

    // ---------------------------------------------------------------- writing

    private static void writeValue(StringBuilder sb, Object value) {
        switch (value) {
            case null -> sb.append("null");
            case String s -> writeString(sb, s);
            case Boolean b -> sb.append(b);
            case Integer i -> sb.append(i);
            case Long l -> sb.append(l);
            case BigDecimal d -> sb.append(d.toPlainString());
            case Map<?, ?> m -> {
                sb.append('{');
                Iterator<? extends Map.Entry<?, ?>> it = m.entrySet().iterator();
                while (it.hasNext()) {
                    Map.Entry<?, ?> e = it.next();
                    writeString(sb, String.valueOf(e.getKey()));
                    sb.append(':');
                    writeValue(sb, e.getValue());
                    if (it.hasNext()) {
                        sb.append(',');
                    }
                }
                sb.append('}');
            }
            case Collection<?> c -> {
                sb.append('[');
                Iterator<?> it = c.iterator();
                while (it.hasNext()) {
                    writeValue(sb, it.next());
                    if (it.hasNext()) {
                        sb.append(',');
                    }
                }
                sb.append(']');
            }
            default -> throw new IllegalArgumentException("Cannot write " + value.getClass() + " as JSON");
        }
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    // '<', '>' and '&' escaped too: values may end up inside HTML/script contexts.
                    if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == 0x2028 || c == 0x2029) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }
}
