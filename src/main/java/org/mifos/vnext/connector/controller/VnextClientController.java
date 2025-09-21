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
package org.mifos.vnext.connector.controller;

import org.mifos.vnext.connector.config.VnextClientConfig;
import org.mifos.vnext.connector.dto.ParticipantRequest;
import org.mifos.vnext.connector.dto.ParticipantResponse;
import org.mifos.vnext.connector.dto.PartyRequestDto;
import org.mifos.vnext.connector.dto.PartyResponseDto;
import org.mifos.vnext.connector.dto.TransferRequestDto;
import org.mifos.vnext.connector.dto.TransferResponseDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins =  "*")
@RestController
public class VnextClientController {
    
    private static Logger logger = LoggerFactory.getLogger(VnextClientController.class);
    
    @Autowired
    private VnextClientConfig vnextClientConfig;
    
    /*
    * API Rest Lookup Participant Information
    */
    @PostMapping(path = "/participant",
                consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ParticipantResponse> getParticipant(@RequestBody ParticipantRequest participantRequest) {
        //Lookup Participant Information
        ParticipantResponse participantResponse = vnextClientConfig.getVNextClient().getParticipant(participantRequest);
        //Prepare the API Rest Response
        if(!participantResponse.isExecutionStatus()){        
            //Return the failure response
            return new ResponseEntity<>(participantResponse, HttpStatus.BAD_REQUEST);
        }
        //Return the success response
        return new ResponseEntity<>(participantResponse, HttpStatus.OK);
    }
    
    /*
    * API Rest Lookup Party Information
    */
    @PostMapping(path = "/partyinfo",
                consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<PartyResponseDto> getPartyInfo(@RequestBody PartyRequestDto partyRequest) {
        //Lookup Party Information
        PartyResponseDto partyResponse = vnextClientConfig.getVNextClient().getPartyInfo(partyRequest);
        //Prepare the API Rest Response
        if(!partyResponse.isExecutionStatus()){        
            //Return the failure response
            return new ResponseEntity<>(partyResponse, HttpStatus.BAD_REQUEST);
        }
        //Return the success response
        return new ResponseEntity<>(partyResponse, HttpStatus.OK);
    }
    
    /*
    * API Rest Execute Money Transfer
    */
    @PostMapping(path = "/executetransfer",
                consumes = MediaType.APPLICATION_JSON_VALUE,
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TransferResponseDto> executeTransfer(@RequestBody TransferRequestDto transferRequest) {
        //Extecute Transfer
        TransferResponseDto transferResponse = vnextClientConfig.getVNextClient().executeTransfer(transferRequest);        
        //Prepare the API Rest Response
        if(!transferResponse.isExecutionStatus()){        
            //Return the failure response
            return new ResponseEntity<>(transferResponse, HttpStatus.BAD_REQUEST);
        }
        //Return the success response
        return new ResponseEntity<>(transferResponse, HttpStatus.OK);
    }
}
