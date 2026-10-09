package br.com.jurishome.auth.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TotpServiceTest {

    private static final String RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    private final TotpService service = new TotpService();

    @Test
    void generatesTheRfc6238Code() {
        assertThat(service.generateCode(RFC_SECRET, 59L / 30L, 8)).isEqualTo("94287082");
    }

    @Test
    void generatedSecretWorksWithTheCurrentTimeWindow() {
        String secret = service.generateSecret();
        String code = service.currentCode(secret);

        assertThat(secret).matches("[A-Z2-7]{32}");
        assertThat(service.verify(secret, code)).isTrue();
    }

    @Test
    void acceptsAControlledClockDifference() {
        long serverCounter = 1_000_000L;
        String phoneCode = service.generateCode(RFC_SECRET, serverCounter - 2, 6);

        assertThat(service.verify(RFC_SECRET, phoneCode, serverCounter)).isTrue();
        assertThat(service.verify(
            RFC_SECRET,
            service.generateCode(RFC_SECRET, serverCounter - 3, 6),
            serverCounter
        )).isFalse();
    }
}
