package br.com.jurishome.auth.service;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;

import org.springframework.stereotype.Service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

@Service
public class TotpService {

    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final int SECRET_SIZE = 20;
    private static final int PERIOD_SECONDS = 30;
    private static final int DIGITS = 6;
    private static final int QR_CODE_SIZE = 280;
    private static final int ALLOWED_TIME_STEPS = 2;

    private final SecureRandom secureRandom = new SecureRandom();

    public String generateSecret() {
        byte[] bytes = new byte[SECRET_SIZE];
        secureRandom.nextBytes(bytes);
        return encodeBase32(bytes);
    }

    public boolean verify(String secret, String submittedCode) {
        long currentCounter = Instant.now().getEpochSecond() / PERIOD_SECONDS;
        return verify(secret, submittedCode, currentCounter);
    }

    boolean verify(String secret, String submittedCode, long currentCounter) {
        if (secret == null || submittedCode == null || !submittedCode.matches("\\d{6}")) {
            return false;
        }

        // Aceita até um minuto de diferença entre o relógio do celular e o do servidor.
        for (long offset = -ALLOWED_TIME_STEPS; offset <= ALLOWED_TIME_STEPS; offset++) {
            String expected = generateCode(secret, currentCounter + offset, DIGITS);
            if (MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.US_ASCII),
                submittedCode.getBytes(StandardCharsets.US_ASCII)
            )) {
                return true;
            }
        }
        return false;
    }

    public String currentCode(String secret) {
        long currentCounter = Instant.now().getEpochSecond() / PERIOD_SECONDS;
        return generateCode(secret, currentCounter, DIGITS);
    }

    public String provisioningUri(String username, String secret) {
        String issuer = "JurisHome";
        String label = urlEncode(issuer + ":" + username);
        return "otpauth://totp/" + label
            + "?secret=" + secret
            + "&issuer=" + urlEncode(issuer)
            + "&algorithm=SHA1&digits=" + DIGITS
            + "&period=" + PERIOD_SECONDS;
    }

    public byte[] createQrCode(String provisioningUri) {
        try {
            Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
            hints.put(EncodeHintType.MARGIN, 1);

            BitMatrix matrix = new QRCodeWriter().encode(
                provisioningUri,
                BarcodeFormat.QR_CODE,
                QR_CODE_SIZE,
                QR_CODE_SIZE,
                hints
            );
            BufferedImage image = new BufferedImage(QR_CODE_SIZE, QR_CODE_SIZE, BufferedImage.TYPE_INT_RGB);
            for (int y = 0; y < QR_CODE_SIZE; y++) {
                for (int x = 0; x < QR_CODE_SIZE; x++) {
                    image.setRGB(x, y, matrix.get(x, y) ? 0xFF000000 : 0xFFFFFFFF);
                }
            }

            ByteArrayOutputStream output = new ByteArrayOutputStream();
            ImageIO.write(image, "PNG", output);
            return output.toByteArray();
        } catch (WriterException | java.io.IOException ex) {
            throw new IllegalStateException("Nao foi possivel gerar o QR Code do autenticador.", ex);
        }
    }

    // O intervalo anterior e o seguinte também são aceitos para compensar pequenas diferenças de relógio.
    String generateCode(String secret, long counter, int digits) {
        try {
            byte[] counterBytes = ByteBuffer.allocate(Long.BYTES).putLong(counter).array();
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(decodeBase32(secret), "HmacSHA1"));
            byte[] hash = mac.doFinal(counterBytes);
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
            int modulus = (int) Math.pow(10, digits);
            return String.format(Locale.ROOT, "%0" + digits + "d", binary % modulus);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Nao foi possivel validar o codigo do autenticador.", ex);
        }
    }

    private String encodeBase32(byte[] bytes) {
        StringBuilder encoded = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte value : bytes) {
            buffer = (buffer << 8) | (value & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                encoded.append(BASE32_ALPHABET.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            encoded.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return encoded.toString();
    }

    private byte[] decodeBase32(String value) {
        String normalized = value.replace("=", "").replace(" ", "").toUpperCase(Locale.ROOT);
        ByteArrayOutputStream decoded = new ByteArrayOutputStream();
        int buffer = 0;
        int bitsLeft = 0;
        for (char character : normalized.toCharArray()) {
            int index = BASE32_ALPHABET.indexOf(character);
            if (index < 0) {
                throw new IllegalArgumentException("Segredo TOTP invalido.");
            }
            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                decoded.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return decoded.toByteArray();
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
