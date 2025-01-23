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
package org.mifos.vnext.connector.rest.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.mx.fintecheando.grpc.proto.mojaloop.ServerAcceptTransferRequest;
import com.mx.fintecheando.grpc.proto.mojaloop.ServerPartyInfoRequest;
import java.math.BigDecimal;
import org.mifos.vnext.connector.dto.AccountDepositServiceRequest;
import org.mifos.vnext.connector.dto.AccountLookupServiceRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.mifos.vnext.connector.dto.AccountDepositServiceResponse;
import org.mifos.vnext.connector.dto.AccountLookupServiceResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class ApacheFineract{

    private static final Logger LOGGER = LoggerFactory.getLogger(ApacheFineract.class);

    @Value("${fineract.api.base-url}")
    private String fineractApiBaseUrl;

    @Value("${fineract.api.username}")
    private String username;

    @Value("${fineract.api.password}")
    private String password;

    static RestTemplate restTemplate = new RestTemplate();  

    public AccountLookupServiceResponse findClientAccount(ServerPartyInfoRequest request) throws Exception {
        String regex = "[,\\.\\s]";
        String displayName ="";
        Integer accountNo = 0;
        String accountNoStr="";
        AccountLookupServiceRequest accountLookupServiceRequest = new AccountLookupServiceRequest();
        accountLookupServiceRequest.setAccount(request.getPartyId());
        accountLookupServiceRequest.setFspId(request.getDestinationFspId());
        accountLookupServiceRequest.setTenant(request.getDestinationFspId());
        ResponseEntity<JsonNode> responseFindClientAccount = sendPostRequest("/quickals", accountLookupServiceRequest);   
        AccountLookupServiceResponse accountLookupServiceResponse = new AccountLookupServiceResponse();
        if(responseFindClientAccount.getStatusCode() == HttpStatus.OK ){
            try {
                LOGGER.debug("Account Lookup Service Response "+responseFindClientAccount.getBody().toPrettyString());                
                displayName = responseFindClientAccount.getBody().get(0).get("parentName").asText();
                String[] myName = displayName.split(regex);
                accountLookupServiceResponse.setFirstName(myName[0]);
                accountLookupServiceResponse.setLastName(myName[1]);
                accountNo = responseFindClientAccount.getBody().get(0).get("entityId").intValue();
                accountNoStr = responseFindClientAccount.getBody().get(0).get("entityAccountNo").asText();                
                accountLookupServiceResponse.setEntityId(accountNo);
                accountLookupServiceResponse.setEntityAccountNo(accountNoStr);
            }
            catch(Exception e){
                LOGGER.error("Error "+e.getMessage());
                LOGGER.error(responseFindClientAccount.getBody().toString());
            }
        }
        return accountLookupServiceResponse;
    }

    public AccountDepositServiceResponse depositToClientAccount(ServerAcceptTransferRequest request, AccountLookupServiceResponse serverPartyInfoRequest) throws Exception {
      
        
        String currentDate = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"));

        // Preparamos los datos para la transferencia
        AccountDepositServiceRequest depositRequest = new AccountDepositServiceRequest();
        depositRequest.setTenant(request.getTo().getFspId());
        depositRequest.setFspId(request.getTo().getFspId());

        // Establecemos la fecha de la transacción con la fecha del sistema
        depositRequest.setTransactionDate(currentDate);
        depositRequest.setDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        depositRequest.setTransactionAmount(new BigDecimal(request.getAmount().getAmount()));
        depositRequest.setPaymentTypeId(1);
        depositRequest.setAccount(serverPartyInfoRequest.getEntityAccountNo());
        depositRequest.setAccountNumber(serverPartyInfoRequest.getEntityId());
        depositRequest.setNote(request.getNote());            
        depositRequest.setLocale("en");

        //return ResponseEntity<JsonNode> depositResponse = sendPostRequest("/deposit", accountDepositServiceRequest); 
        
        ResponseEntity<JsonNode> responseDeposit = sendPostRequest("/deposit", depositRequest);           
        AccountDepositServiceResponse accountDepositServiceResponse = new AccountDepositServiceResponse();
        
        if(responseDeposit.getStatusCode() == HttpStatus.OK ){
            try {
                LOGGER.debug("Account Lookup Service Response "+responseDeposit.getBody());                
                accountDepositServiceResponse.setOfficeId(responseDeposit.getBody().get("officeId").intValue());
                accountDepositServiceResponse.setClientId(responseDeposit.getBody().get("clientId").intValue());
                accountDepositServiceResponse.setSavingsId(responseDeposit.getBody().get("savingsId").intValue());
                accountDepositServiceResponse.setResourceId(responseDeposit.getBody().get("resourceId").intValue());
            }
            catch(Exception e){
                LOGGER.error("Error "+e.getMessage());
                LOGGER.error(responseDeposit.getBody().toString());
            }
        }
        return accountDepositServiceResponse;
        
    }

    private ResponseEntity<JsonNode> sendPostRequest(String path, Object requestBody) throws Exception {
        String url = fineractApiBaseUrl + path;

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", getBasicAuthenticationHeader(username, password));

        ObjectWriter ow = new ObjectMapper().writer().withDefaultPrettyPrinter();
        String json = ow.writeValueAsString(requestBody);

        HttpEntity<String> entity = new HttpEntity<>(json, headers);
        LOGGER.debug("Sending request to {} with body: {}", url, json);

        return restTemplate.exchange(URI.create(url),HttpMethod.POST, entity, JsonNode.class);
    }

    private String getBasicAuthenticationHeader(String username, String password) {
        String credentials = username + ":" + password;
        return "Basic " + java.util.Base64.getEncoder().encodeToString(credentials.getBytes());
    }
}