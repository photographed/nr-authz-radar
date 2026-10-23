package io.github.photographed.authzradar;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PseudonymizerTest {

    @Test
    void sameInputSameKeyGivesSamePseudonym() {
        Pseudonymizer p = new Pseudonymizer("k1");
        assertThat(p.user("alice")).isEqualTo(p.user("alice")).startsWith("u_").hasSize(18);
        assertThat(p.apiKey("secret-key")).startsWith("k_").hasSize(10);
    }

    @Test
    void differentKeysGiveDifferentPseudonyms() {
        assertThat(new Pseudonymizer("k1").user("alice")).isNotEqualTo(new Pseudonymizer("k2").user("alice"));
    }

    @Test
    void neverContainsTheRawValue() {
        assertThat(new Pseudonymizer("k1").user("alice")).doesNotContain("alice");
    }

    @Test
    void matchesTheOtherLanguages() {
        // Same value as python/node/ruby/go/php (tests/test_languages.py): enduser.id stays
        // comparable across services written in different languages.
        assertThat(new Pseudonymizer("k").user("alice")).isEqualTo("u_ec631a55bb81f5b9");
    }

    @Test
    void withoutKeyNothingIsProduced() {
        assertThat(new Pseudonymizer(null).user("alice")).isNull();
        assertThat(new Pseudonymizer(" ").enabled()).isFalse();
    }
}
