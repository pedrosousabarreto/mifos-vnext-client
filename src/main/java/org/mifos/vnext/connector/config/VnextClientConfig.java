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

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.mifos.vnext.connector.rest.client.ApacheFineract;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class VnextClientConfig {

    private static final Logger logger = LoggerFactory.getLogger(VnextClientConfig.class);
    private VnextClient vnextclient;

    @Value("${pch.vnext.fspid}")
    private String pchVnextFspId;

    @Value("${pch.vnext.client.name}")
    private String pchVnextClientName;

    @Value("${pch.vnext.client.version:1.0}") // Valor por defecto
    private String pchVnextClientVersion;

    @Value("${pch.vnext.server.port}")
    private int pchVnextServerPort;

    @Value("${pch.vnext.server.dns}")
    private String pchVnextServerDNS;

    @Value("${pch.vnext.server.certificate}")
    private String pchVnextServerCertificate;

    @Value("${pch.vnext.client.private.key}") // Nueva propiedad
    private String pchVnextClientPrivateKey;

    @Value("${pch.vnext.ca.certificate}") // Nueva propiedad
    private String pchVnextCaCertificate;

    @Value("${pch.vnext.client.certificate}") // Nueva propiedad
    private String pchVnextClientCertificate;

    @Value("${pch.vnext.main.client:true}") // Nueva propiedad con valor por defecto
    private boolean pchVnextMainClient;

    @Value("${pch.vnext.server.keep-alive-time:10000}") // Valor por defecto
    private int pchVnextKeepAliveTime;

    @Value("${pch.vnext.server.keep-alive-timeout:5000}") // Valor por defecto
    private int pchVnextKeepAliveTimeout;

    @Value("${pch.vnext.server.keep-alive-without-calls:true}") // Valor por defecto
    private boolean pchVnextKeepAliveTimeWithoutCalls;

    @Autowired
    private ApacheFineract apacheFineract;

    @PostConstruct
    public void initDevelopmentProperties() {
        try {
            logger.info("Initializing VnextClient with FSP ID: {}", pchVnextFspId);
            logger.debug("Client Name: {}, Version: {}", pchVnextClientName, pchVnextClientVersion);
            logger.debug("Server: {}:{}", pchVnextServerDNS, pchVnextServerPort);

            // Validar que las propiedades requeridas estén presentes
            validateRequiredProperties();

            this.vnextclient = new VnextClient(

                    pchVnextFspId,
                    pchVnextClientName,
                    pchVnextClientVersion,
                    pchVnextClientPrivateKey,
                    pchVnextCaCertificate,
                    pchVnextClientCertificate,
                    pchVnextMainClient,
                    pchVnextServerDNS,
                    pchVnextServerPort,
                    pchVnextServerCertificate,
                    pchVnextKeepAliveTime,
                    pchVnextKeepAliveTimeout,
                    pchVnextKeepAliveTimeWithoutCalls,
                    apacheFineract
            );

            boolean started = vnextclient.start();
            if (started) {
                logger.info("VnextClient started successfully");
            } else {
                logger.error("Failed to start VnextClient");
                throw new RuntimeException("Failed to start VnextClient");
            }

        } catch (Exception e) {
            logger.error("Failed to initialize VnextClient", e);
            throw new RuntimeException("VnextClient initialization failed", e);
        }
    }

    private void validateRequiredProperties() {
        if (pchVnextFspId == null || pchVnextFspId.trim().isEmpty()) {
            throw new IllegalArgumentException("pch.vnext.fspid is required");
        }
        if (pchVnextClientName == null || pchVnextClientName.trim().isEmpty()) {
            throw new IllegalArgumentException("pch.vnext.client.name is required");
        }
        if (pchVnextServerDNS == null || pchVnextServerDNS.trim().isEmpty()) {
            throw new IllegalArgumentException("pch.vnext.server.dns is required");
        }
        if (pchVnextServerCertificate == null || pchVnextServerCertificate.trim().isEmpty()) {
            throw new IllegalArgumentException("pch.vnext.server.certificate is required");
        }
        if (pchVnextClientPrivateKey == null || pchVnextClientPrivateKey.trim().isEmpty()) {
            throw new IllegalArgumentException("pch.vnext.client.private.key is required for authentication");
        }
        if (pchVnextCaCertificate == null || pchVnextCaCertificate.trim().isEmpty()) {
            throw new IllegalArgumentException("pch.vnext.ca.certificate is required for authentication");
        }
        if (pchVnextClientCertificate == null || pchVnextClientCertificate.trim().isEmpty()) {
            throw new IllegalArgumentException("pch.vnext.client.certificate is required for authentication");
        }
    }

    @PreDestroy
    public void destroy() {
        try {
            if (vnextclient != null) {
                logger.info("Shutting down VnextClient...");
                vnextclient.shutdown();
                logger.info("VnextClient shutdown completed");
            }
        } catch (Exception e) {
            logger.error("Error during VnextClient shutdown: {}", e.getMessage(), e);
        }
    }

    public VnextClient getVNextClient() {
        if (vnextclient == null) {
            throw new IllegalStateException("VnextClient is not initialized");
        }
        return vnextclient;
    }

    // Métodos de utilidad para verificar el estado
    public boolean isClientInitialized() {
        return vnextclient != null;
    }

    public boolean isClientAuthenticated() {
        return vnextclient != null && vnextclient.isAuthenticated();
    }

    public String getClientStatus() {
        if (vnextclient == null) {
            return "NOT_INITIALIZED";
        } else if (vnextclient.isAuthenticated()) {
            return "AUTHENTICATED";
        } else {
            return "INITIALIZED_BUT_NOT_AUTHENTICATED";
        }
    }
}