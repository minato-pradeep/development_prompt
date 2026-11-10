package com.userrepo.auth.company;

import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.config.AppProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.awt.image.BufferedImage;
import java.awt.Color;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

import javax.imageio.ImageIO;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LogoStorageServiceTest {

    private AppProperties buildProps(long maxBytes, int maxDim) {
        return new AppProperties(
                new AppProperties.Tokens("http://localhost", "http://localhost/platform",
                        900,900,43200,1800,259200,86400,1209600,2592000,604800,true),
                new AppProperties.Password(12,5,5,false,259200),
                new AppProperties.Totp(30,6,"HmacSHA1",1,10),
                new AppProperties.RateLimit("postgres"),
                new AppProperties.Bootstrap("X"),
                new AppProperties.Encryption(new AppProperties.Encryption.TotpSecret("K","KID")),
                new AppProperties.Logo(maxBytes, maxDim, maxDim, List.of("image/png","image/jpeg"))
        );
    }

    private byte[] pngBytes(int w, int h) throws Exception {
        BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        img.setRGB(0, 0, Color.BLUE.getRGB());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(img, "png", out);
        return out.toByteArray();
    }

    @Test
    void store_validPng_succeeds(@TempDir Path tmp) throws Exception {
        LogoStorageService svc = new LogoStorageService(buildProps(5_000_000, 1024), tmp.toString());
        byte[] bytes = pngBytes(100, 100);
        LogoStorageService.StoredLogo result = svc.store(UUID.randomUUID(), "test.png", "image/png", bytes);
        assertThat(result.contentType()).isEqualTo("image/png");
        assertThat(result.widthPx()).isEqualTo(100);
    }

    @Test
    void store_svgBytes_throwsValidationError(@TempDir Path tmp) {
        LogoStorageService svc = new LogoStorageService(buildProps(5_000_000, 1024), tmp.toString());
        byte[] svgBytes = "<svg xmlns='http://www.w3.org/2000/svg'></svg>".getBytes();
        assertThatThrownBy(() -> svc.store(UUID.randomUUID(), "test.svg", "image/svg+xml", svgBytes))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void store_exceedMaxSize_throwsValidationError(@TempDir Path tmp) throws Exception {
        LogoStorageService svc = new LogoStorageService(buildProps(10, 1024), tmp.toString());
        byte[] bytes = pngBytes(10, 10);
        assertThatThrownBy(() -> svc.store(UUID.randomUUID(), "big.png", "image/png", bytes))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void store_exceedDimension_throwsValidationError(@TempDir Path tmp) throws Exception {
        LogoStorageService svc = new LogoStorageService(buildProps(5_000_000, 50), tmp.toString());
        byte[] bytes = pngBytes(100, 100);
        assertThatThrownBy(() -> svc.store(UUID.randomUUID(), "big.png", "image/png", bytes))
                .isInstanceOf(AuthException.class);
    }
}
