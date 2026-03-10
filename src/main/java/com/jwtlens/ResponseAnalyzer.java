package com.jwtlens;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Analyzes HTTP responses to determine if a modified JWT was accepted.
 * Uses multiple heuristics: status code, response length similarity, and key phrases.
 */
public class ResponseAnalyzer {

    /**
     * Determines if the check response indicates the server accepted the modified JWT.
     * Compares against the baseline (original valid request) response.
     */
    public static boolean isAccepted(HttpRequestResponse baseline, HttpRequestResponse check) {
        if (baseline == null || check == null) return false;
        HttpResponse baseResp = baseline.response();
        HttpResponse checkResp = check.response();
        if (baseResp == null || checkResp == null) return false;

        short baseStatus = baseResp.statusCode();
        short checkStatus = checkResp.statusCode();

        // If check response is a clear auth failure, not accepted
        if (checkStatus == 401 || checkStatus == 403) {
            return false;
        }

        // If check response is a server error, not a clean accept
        if (checkStatus >= 500) {
            return false;
        }

        // If same status code as baseline, likely accepted
        if (baseStatus == checkStatus) {
            // Additional check: response body length should be within 30% of baseline
            int baseLen = baseResp.body().length();
            int checkLen = checkResp.body().length();
            if (baseLen == 0 && checkLen == 0) return true;
            if (baseLen == 0) return checkLen < 100; // small response still might be accepted
            double ratio = (double) checkLen / baseLen;
            return ratio > 0.5 && ratio < 2.0;
        }

        // If baseline was 200 and check is a redirect, might be accepted in some cases
        if (baseStatus == 200 && (checkStatus == 301 || checkStatus == 302)) {
            return false; // Usually a redirect means "go login"
        }

        // If check returns 200 and baseline was something else, likely accepted
        if (checkStatus == 200) {
            return true;
        }

        return false;
    }

    /**
     * Checks if the response indicates a server error (useful for error-based detection).
     */
    public static boolean isServerError(HttpRequestResponse response) {
        if (response == null || response.response() == null) return false;
        return response.response().statusCode() >= 500;
    }

    /**
     * Checks if response time suggests a time-based injection (e.g., sleep in kid).
     * Returns true if response took significantly longer than baseline.
     */
    public static boolean isTimeBased(long baselineMs, long checkMs, long thresholdMs) {
        return (checkMs - baselineMs) > thresholdMs;
    }

    /**
     * Gets the status code from a response, or -1 if unavailable.
     */
    public static int getStatusCode(HttpRequestResponse response) {
        if (response == null || response.response() == null) return -1;
        return response.response().statusCode();
    }

    /**
     * Extracts a snippet of the response body for display in findings.
     */
    public static String getResponseSnippet(HttpRequestResponse response, int maxLength) {
        if (response == null || response.response() == null) return "";
        String body = response.response().bodyToString();
        if (body.length() <= maxLength) return body;
        return body.substring(0, maxLength) + "...";
    }
}
