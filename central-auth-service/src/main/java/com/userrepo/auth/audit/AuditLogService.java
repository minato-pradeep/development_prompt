package com.userrepo.auth.audit;

import com.userrepo.auth.common.TraceIds;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Append-only audit recording (Section 19). Recorded in its own transaction so
 * that a failure in the audited operation still leaves an audit trail. Never
 * logs plaintext passwords, OTPs, TOTP secrets, tokens or recovery codes; only
 * opaque identifiers and non-sensitive metadata are stored.
 */
@Service
public class AuditLogService {

    private static final Logger log = LoggerFactory.getLogger(AuditLogService.class);

    private final AuditLogRepository repository;
    private final ObjectMapper objectMapper;

    public AuditLogService(AuditLogRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEventType type, String actorType, UUID actorId, UUID companyId,
                       String targetType, UUID targetId, String result,
                       String ipAddress, Map<String, Object> metadata) {
        try {
            AuditLog entry = new AuditLog();
            entry.setEventType(type);
            entry.setActorType(actorType);
            entry.setActorId(actorId);
            entry.setCompanyId(companyId);
            entry.setTargetType(targetType);
            entry.setTargetId(targetId);
            entry.setResult(result);
            entry.setCorrelationId(TraceIds.current());
            entry.setIpAddress(ipAddress);
            entry.setMetadata(toJson(metadata));
            repository.save(entry);
        } catch (Exception e) {
            // Audit must not break the protected operation; log and continue.
            log.error("Failed to write audit record for {}: {}", type, e.getMessage(), e);
        }
    }

    /** Convenience builder for the common case. */
    public AuditEntryBuilder builder(AuditEventType type) {
        return new AuditEntryBuilder(this, type);
    }

    private String toJson(Map<String, Object> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(metadata);
        } catch (Exception e) {
            // Fall back to a minimal representation; never throw from audit.
            return "{\"error\":\"metadata serialization failed\"}";
        }
    }

    public static final class AuditEntryBuilder {
        private final AuditLogService service;
        private final AuditEventType type;
        private String actorType;
        private UUID actorId;
        private UUID companyId;
        private String targetType;
        private UUID targetId;
        private String result = "SUCCESS";
        private String ipAddress;
        private final Map<String, Object> metadata = new LinkedHashMap<>();

        AuditEntryBuilder(AuditLogService service, AuditEventType type) {
            this.service = service;
            this.type = type;
        }

        public AuditEntryBuilder actor(String actorType, UUID actorId) {
            this.actorType = actorType;
            this.actorId = actorId;
            return this;
        }

        public AuditEntryBuilder company(UUID companyId) {
            this.companyId = companyId;
            return this;
        }

        public AuditEntryBuilder target(String targetType, UUID targetId) {
            this.targetType = targetType;
            this.targetId = targetId;
            return this;
        }

        public AuditEntryBuilder result(String result) {
            this.result = result;
            return this;
        }

        public AuditEntryBuilder ip(String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }

        public AuditEntryBuilder meta(String key, Object value) {
            this.metadata.put(key, value);
            return this;
        }

        public void record() {
            service.record(type, actorType, actorId, companyId, targetType, targetId,
                    result, ipAddress, metadata);
        }
    }
}
