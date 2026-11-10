package com.userrepo.auth.company;

import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "company_settings")
public class CompanySettings {

    @Id
    @Column(name = "company_id", updatable = false, nullable = false)
    private UUID companyId;

    @Column(name = "date_format", nullable = false)
    private String dateFormat = "YYYY-MM-DD";

    @Column(name = "email_unique_per_company", nullable = false)
    private boolean emailUniquePerCompany = true;

    @Column(name = "max_concurrent_sessions", nullable = false)
    private int maxConcurrentSessions = 5;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public CompanySettings() {}

    public UUID getCompanyId() { return companyId; }
    public void setCompanyId(UUID companyId) { this.companyId = companyId; }
    public String getDateFormat() { return dateFormat; }
    public void setDateFormat(String dateFormat) { this.dateFormat = dateFormat; }
    public boolean isEmailUniquePerCompany() { return emailUniquePerCompany; }
    public void setEmailUniquePerCompany(boolean emailUniquePerCompany) { this.emailUniquePerCompany = emailUniquePerCompany; }
    public int getMaxConcurrentSessions() { return maxConcurrentSessions; }
    public void setMaxConcurrentSessions(int maxConcurrentSessions) { this.maxConcurrentSessions = maxConcurrentSessions; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
