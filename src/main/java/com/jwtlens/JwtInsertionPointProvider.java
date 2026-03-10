package com.jwtlens;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import java.util.ArrayList;
import java.util.List;

/**
 * Provides JWT insertion points for the Burp scanner.
 * Finds JWTs in Authorization headers, cookies, request body, and URL parameters.
 */
public class JwtInsertionPointProvider implements burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider {

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse baseRequestResponse) {
        List<AuditInsertionPoint> insertionPoints = new ArrayList<>();
        String request = baseRequestResponse.request().toString();

        // Find all JWTs in the request
        List<JwtToken.JwtLocation> locations = JwtToken.extractWithLocation(request);

        for (JwtToken.JwtLocation loc : locations) {
            insertionPoints.add(
                    AuditInsertionPoint.auditInsertionPoint(
                            "JWTLens: JWT Token",
                            baseRequestResponse.request(),
                            loc.startIndex,
                            loc.endIndex
                    )
            );
        }

        return insertionPoints;
    }
}
