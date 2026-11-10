package com.userrepo.auth.company;

import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.config.AppProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Set;
import java.util.UUID;

/**
 * Private storage abstraction for company logos (Section 8).
 *
 * <p>Validation rules enforced here:
 * <ul>
 *   <li>SVG is forbidden.
 *   <li>Only PNG and JPEG allowed.
 *   <li>Max file size and pixel dimensions enforced.
 *   <li>Actual content (magic bytes) validated, not just the declared type.
 *   <li>Image is re-encoded (strips metadata).
 * </ul>
 *
 * <p>In development, files are stored in a local private directory
 * ({@code app.logo.storage-path}, default {@code ./storage/logos}).
 * For production, replace with an S3-compatible adapter.
 */
@Service
public class LogoStorageService {

    private static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/jpeg");
    private static final byte[] PNG_MAGIC = {(byte) 0x89, 0x50, 0x4E, 0x47};
    private static final byte[] JPEG_MAGIC = {(byte) 0xFF, (byte) 0xD8, (byte) 0xFF};

    private final AppProperties properties;
    private final Path storageRoot;

    public LogoStorageService(AppProperties properties,
                               @Value("${app.logo.storage-path:./storage/logos}") String storagePath) {
        this.properties = properties;
        this.storageRoot = Paths.get(storagePath).toAbsolutePath().normalize();
    }

    public record StoredLogo(String storedPath, String contentType, long sizeBytes,
                             int widthPx, int heightPx) {}

    public StoredLogo store(UUID companyId, String originalName, String declaredContentType,
                            byte[] bytes) {
        AppProperties.Logo cfg = properties.logo();

        // 1. Size check.
        if (bytes.length > cfg.maxSizeBytes()) {
            throw new AuthException(AuthErrorCode.VALIDATION_ERROR,
                    "Logo file size exceeds maximum of " + cfg.maxSizeBytes() + " bytes");
        }

        // 2. Magic-byte validation (content sniffing, not just declared type).
        String detectedType = detectContentType(bytes);
        if (detectedType == null || !ALLOWED_TYPES.contains(detectedType)) {
            throw new AuthException(AuthErrorCode.VALIDATION_ERROR,
                    "Logo must be PNG or JPEG. SVG and other formats are forbidden.");
        }

        // 3. Re-encode via ImageIO to strip metadata and validate the image fully.
        BufferedImage image;
        try {
            image = ImageIO.read(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            throw new AuthException(AuthErrorCode.VALIDATION_ERROR,
                    "Logo file could not be decoded as a valid image");
        }
        if (image == null) {
            throw new AuthException(AuthErrorCode.VALIDATION_ERROR, "Logo is not a valid image");
        }

        // 4. Dimension check.
        if (image.getWidth() > cfg.maxWidthPx() || image.getHeight() > cfg.maxHeightPx()) {
            throw new AuthException(AuthErrorCode.VALIDATION_ERROR,
                    "Logo dimensions exceed " + cfg.maxWidthPx() + "x" + cfg.maxHeightPx() + " px");
        }

        // 5. Re-encode to strip all metadata.
        String format = "jpeg".equals(detectedType.replace("image/", "")) ? "jpeg" : "png";
        String resolvedType = "image/" + format;
        byte[] reEncoded = reEncode(image, format);

        // 6. Store under a private path (never served directly; accessed via controller).
        String filename = companyId + "_" + UUID.randomUUID() + "." + format;
        Path dir = storageRoot.resolve(companyId.toString());
        try {
            Files.createDirectories(dir);
            Path dest = dir.resolve(filename);
            Files.copy(new ByteArrayInputStream(reEncoded), dest, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new AuthException(AuthErrorCode.INTERNAL_ERROR, "Failed to store logo file");
        }

        String storedPath = companyId + "/" + filename;
        return new StoredLogo(storedPath, resolvedType, reEncoded.length,
                image.getWidth(), image.getHeight());
    }

    public InputStream load(String storedPath) throws IOException {
        Path file = storageRoot.resolve(storedPath).normalize();
        if (!file.startsWith(storageRoot)) {
            throw new AuthException(AuthErrorCode.FORBIDDEN, "Invalid storage path");
        }
        return Files.newInputStream(file);
    }

    public void delete(String storedPath) {
        try {
            Path file = storageRoot.resolve(storedPath).normalize();
            if (file.startsWith(storageRoot)) {
                Files.deleteIfExists(file);
            }
        } catch (IOException ignored) {
        }
    }

    private static String detectContentType(byte[] bytes) {
        if (bytes.length >= 3
                && (bytes[0] & 0xFF) == (PNG_MAGIC[0] & 0xFF)
                && (bytes[1] & 0xFF) == (PNG_MAGIC[1] & 0xFF)
                && (bytes[2] & 0xFF) == (PNG_MAGIC[2] & 0xFF)
                && bytes.length >= 4
                && (bytes[3] & 0xFF) == (PNG_MAGIC[3] & 0xFF)) {
            return "image/png";
        }
        if (bytes.length >= 3
                && (bytes[0] & 0xFF) == (JPEG_MAGIC[0] & 0xFF)
                && (bytes[1] & 0xFF) == (JPEG_MAGIC[1] & 0xFF)
                && (bytes[2] & 0xFF) == (JPEG_MAGIC[2] & 0xFF)) {
            return "image/jpeg";
        }
        return null;
    }

    private static byte[] reEncode(BufferedImage image, String format) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        try {
            ImageIO.write(image, format, out);
        } catch (IOException e) {
            throw new AuthException(AuthErrorCode.INTERNAL_ERROR, "Failed to re-encode logo image");
        }
        return out.toByteArray();
    }
}
