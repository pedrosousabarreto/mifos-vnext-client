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
    
    private static Logger logger = LoggerFactory.getLogger(VnextClientConfig.class);
    VnextClient vnextclient;
    
    @Value("${pch.vnext.fspid}")
    private String pchVnextFspId;
    
    @Value("${pch.vnext.access.token}")
    private String pchVnextAccessToken;
    
    @Value("${pch.vnext.client.name}")
    private String pchVnextClientName;
    
    @Value("${pch.vnext.server.port}")
    private int pchVnextServerPort;
    
    @Value("${pch.vnext.server.dns}")
    private String pchVnextServerDNS;
        
    @Value("${pch.vnext.server.certificate}")
    private String pchVnextServerCertificate;
    
    @Value("${pch.vnext.server.keep-alive-time}")
    private int pchVnextKeepAliveTime;
    
    @Value("${pch.vnext.server.keep-alive-timeout}")
    private int pchVnextKeepAliveTimeout;
    
    @Value("${pch.vnext.server.keep-alive-without-calls}")
    private boolean pchVnextKeepAliveTimeWithoutCalls;
    
    @Autowired
    private ApacheFineract apacheFineract;        
    
    @PostConstruct
    public void initDevelopmentProperties() throws Exception {            
        this.vnextclient = new VnextClient(pchVnextAccessToken, pchVnextFspId, 
                pchVnextClientName, pchVnextServerDNS, 
                pchVnextServerPort, pchVnextServerCertificate,
                pchVnextKeepAliveTime, pchVnextKeepAliveTimeout,
                pchVnextKeepAliveTimeWithoutCalls, apacheFineract);
        vnextclient.start();        
    }
    
    @PreDestroy
    public void destroy() {
        try{
            vnextclient.shutdown();
        }
        catch (Exception e){
            logger.error("Shutdown Error "+e.getMessage());
        }
    }
    
    public VnextClient getVNextClient(){
        return vnextclient;
    }    
}
