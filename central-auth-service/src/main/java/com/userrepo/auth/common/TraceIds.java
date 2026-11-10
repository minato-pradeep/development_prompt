package com.userrepo.auth.common;

import org.slf4j.MDC;

/** Tiny helper to read the current trace id from the MDC set by {@link TraceIdFilter}. */
public final class TraceIds {

    private TraceIds() {
    }

    public static String current() {
        String id = MDC.get(TraceIdFilter.MDC_KEY);
        return id != null ? id : "n/a";
    }
}
