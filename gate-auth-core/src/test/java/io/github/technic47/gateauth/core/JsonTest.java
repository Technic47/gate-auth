package io.github.technic47.gateauth.core;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JsonTest {

    @Test
    void parsesAllValueTypes() {
        Map<String, Object> m = Json.parseObject(
                " {\"s\":\"a\\\"b\\u0041\",\"i\":-12,\"d\":1.5,\"t\":true,\"f\":false,\"n\":null,\"a\":[1,\"x\",[]],\"o\":{}} ");
        assertThat(m.get("s")).isEqualTo("a\"bA");
        assertThat(m.get("i")).isEqualTo(-12L);
        assertThat(m.get("d").toString()).isEqualTo("1.5");
        assertThat(m.get("t")).isEqualTo(true);
        assertThat(m.get("f")).isEqualTo(false);
        assertThat(m).containsEntry("n", null);
        assertThat((List<?>) m.get("a")).hasSize(3);
        assertThat((Map<?, ?>) m.get("o")).isEmpty();
    }

    @Test
    void roundTrip() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", "Пётр <script>&\n");
        m.put("n", 5L);
        m.put("list", List.of("a", "b"));
        String json = Json.write(m);
        assertThat(json).doesNotContain("<").doesNotContain(">").doesNotContain("&");
        assertThat(Json.parseObject(json)).isEqualTo(m);
    }

    @Test
    void rejectsInvalid() {
        for (String bad : List.of("{", "{\"a\":1,}", "{\"a\":1}x", "{a:1}", "{\"a\":1,\"a\":2}", "[1 2]", "\"\u0001\"",
                "{\"a\":tru}", "[".repeat(100))) {
            assertThatThrownBy(() -> Json.parse(bad)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
