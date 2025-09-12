/**
 * Licensed to the Mifos Initiative under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.mifos.vnext.connector.config;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall.SimpleForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Getter
@Setter
public class HeaderClientInterceptor implements ClientInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(HeaderClientInterceptor.class);

    // Metadata keys as defined in the requirements
    public static final Metadata.Key<String> CLIENT_ID_KEY =
            Metadata.Key.of("clientId", Metadata.ASCII_STRING_MARSHALLER);

    public static final Metadata.Key<String> SESSION_SECRET_KEY =
            Metadata.Key.of("sessionSecret", Metadata.ASCII_STRING_MARSHALLER);

    // Your existing metadata keys (keep for backward compatibility if needed)
    public static final Metadata.Key<String> ACCESS_TOKEN_KEY =
            Metadata.Key.of("accessToken", Metadata.ASCII_STRING_MARSHALLER);

    public static final Metadata.Key<String> FSP_ID_KEY =
            Metadata.Key.of("fspId", Metadata.ASCII_STRING_MARSHALLER);

    private String clientId;
    private String sessionSecret;
    private final String fspId;

    public HeaderClientInterceptor(String fspId) {
        this.sessionSecret = null;
        this.fspId = fspId;
    }

    // Set client ID (generated during stream initialization)
    public void setClientId(String clientId) {
        this.clientId = clientId;
        logger.debug("Client ID set to: {}", clientId);
    }

    // Set session secret (received after successful authentication)
    public void setSessionSecret(String sessionSecret) {
        this.sessionSecret = sessionSecret;
        logger.debug("Session secret set (length: {})", sessionSecret != null ? sessionSecret.length() : 0);
    }

    public boolean isAuthenticated() {
        return sessionSecret != null && !sessionSecret.trim().isEmpty();
    }

    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
            MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {

        return new SimpleForwardingClientCall<ReqT, RespT>(next.newCall(method, callOptions)) {
            @Override
            public void start(ClientCall.Listener<RespT> responseListener, Metadata headers) {

                // Step 1: Always add clientId for authentication (required by gRPC spec)
                if (clientId != null && !clientId.trim().isEmpty()) {
                    headers.put(CLIENT_ID_KEY, clientId);
                    logger.debug("Added clientId header: {}", clientId);
                } else {
                    logger.warn("clientId is null or empty - authentication may fail");
                }

                // Step 2: Add session secret if available (required after authentication)
                if (sessionSecret != null && !sessionSecret.trim().isEmpty()) {
                    headers.put(SESSION_SECRET_KEY, sessionSecret);
                    logger.debug("Added sessionSecret header");
                } else {
                    logger.debug("No session secret available (not authenticated yet)");
                }

                // Step 4: Add FSP ID if available
                if (fspId != null && !fspId.trim().isEmpty()) {
                    headers.put(FSP_ID_KEY, fspId);
                    logger.debug("Added fspId header: {}", fspId);
                }

                // Log the headers being sent (for debugging)
                if (logger.isTraceEnabled()) {
                    logHeaders(headers);
                }

                super.start(responseListener, headers);
            }
        };
    }

    private void logHeaders(Metadata headers) {
        StringBuilder headerLog = new StringBuilder("Sending headers: ");
        if (headers.containsKey(CLIENT_ID_KEY)) {
            headerLog.append("clientId=[present], ");
        }
        if (headers.containsKey(SESSION_SECRET_KEY)) {
            headerLog.append("sessionSecret=[present], ");
        }
        if (headers.containsKey(ACCESS_TOKEN_KEY)) {
            headerLog.append("accessToken=[present], ");
        }
        if (headers.containsKey(FSP_ID_KEY)) {
            headerLog.append("fspId=[present]");
        }
        logger.trace(headerLog.toString());
    }

    // Helper method to clear session (for reauthentication)
    public void clearSession() {
        this.sessionSecret = null;
        logger.debug("Session cleared");
    }

    // Helper method to check if we have the minimum required headers for authentication
    public boolean hasRequiredAuthHeaders() {
        return clientId != null && !clientId.trim().isEmpty();
    }
}