package com.jwtlens;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Deduplication tracker for JWT tokens.
 * Ensures we only scan each unique JWT once per host.
 * Key = (host, jwt_signature_hash) to avoid re-scanning the same token
 * seen across multiple endpoints on the same host.
 */
public class JwtDedup {

    private final ConcurrentHashMap<String, Boolean> seen = new ConcurrentHashMap<>();

    /**
     * Returns true if this JWT has already been seen for this host.
     * If not seen, marks it as seen and returns false.
     */
    public boolean isDuplicate(String host, JwtToken token) {
        String key = host + "|" + token.getSignature().hashCode();
        return seen.putIfAbsent(key, Boolean.TRUE) != null;
    }

    /**
     * Returns true if this JWT has already been seen for this host (passive variant).
     * Uses a separate namespace to avoid interfering with active scans.
     */
    public boolean isDuplicatePassive(String host, JwtToken token) {
        String key = "passive|" + host + "|" + token.getSignature().hashCode();
        return seen.putIfAbsent(key, Boolean.TRUE) != null;
    }

    /**
     * Clears all dedup state.
     */
    public void clear() {
        seen.clear();
    }

    /**
     * Returns the number of unique JWTs tracked.
     */
    public int size() {
        return seen.size();
    }
}
