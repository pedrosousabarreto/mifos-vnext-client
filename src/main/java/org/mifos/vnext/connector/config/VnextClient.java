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

import org.mifos.grpc.proto.vnext.InteropGrpcApiGrpc;
import org.mifos.grpc.proto.vnext.LookupParticipantRequest;
import org.mifos.grpc.proto.vnext.LookupParticipantResponse;
import org.mifos.grpc.proto.vnext.LookupPartyRequest;
import org.mifos.grpc.proto.vnext.LookupPartyResponse;
import org.mifos.grpc.proto.vnext.LookupPartySuccessResponse;
import org.mifos.grpc.proto.vnext.ServerAcceptTransferRequest;
import org.mifos.grpc.proto.vnext.ServerAcceptTransferResponse;
import org.mifos.grpc.proto.vnext.ServerPartyInfoRequest;
import org.mifos.grpc.proto.vnext.StreamClientInitialRequest;
import org.mifos.grpc.proto.vnext.StreamFromClientMsg;
import org.mifos.grpc.proto.vnext.StreamToClientMsg;
import org.mifos.grpc.proto.vnext.TransferRequest;
import org.mifos.grpc.proto.vnext.TransferResponse;

import io.grpc.Channel;
import io.grpc.ClientInterceptor;
import io.grpc.ClientInterceptors;
import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.TlsChannelCredentials;
import io.grpc.stub.StreamObserver;

import java.io.File;
import java.io.IOException;

import java.util.concurrent.TimeUnit;
import org.mifos.vnext.connector.dto.AccountDepositServiceResponse;
import org.mifos.vnext.connector.dto.AccountLookupServiceResponse;
import org.mifos.vnext.connector.dto.ParticipantRequest;
import org.mifos.vnext.connector.dto.ParticipantResponse;
import org.mifos.vnext.connector.dto.PartyRequestDto;
import org.mifos.vnext.connector.dto.PartyResponseDto;
import org.mifos.vnext.connector.dto.TransferRequestDto;
import org.mifos.vnext.connector.dto.TransferResponseDto;
import org.mifos.vnext.connector.rest.client.ApacheFineract;
import org.mifos.vnext.connector.rest.client.VNextClientMapper;
import static org.mifos.vnext.connector.rest.client.VNextClientMapper.mapToAmount;
import static org.mifos.vnext.connector.rest.client.VNextClientMapper.mapToParty;
import static org.mifos.vnext.connector.rest.client.VNextClientMapper.mapToTransactionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VnextClient {
    
    private static Logger logger = LoggerFactory.getLogger(VnextClient.class);
    private final ManagedChannel channel;
    private final Channel channelWithHeader;
    private final InteropGrpcApiGrpc.InteropGrpcApiStub connectionToVnext;    
    private final InteropGrpcApiGrpc.InteropGrpcApiBlockingStub connectionToBlockingVnext;
    private StreamObserver<StreamFromClientMsg> streamFromClientMessageObserver;
    private boolean Loggined = false;
    private final String pchVnextFspId;    
    private final String pchVnextClientName;    
    private final ApacheFineract apacheFineract;
    
    public VnextClient(String pchVnextAccessToken, String pchVnextFspId, 
            String pchVnextClientName, String pchVnextServerDNS, 
            int pchVnextServerPort, String pchVnextServerCertificate,
            int pchVnextKeepAliveTime, int pchVnextKeepAliveTimeout, 
            boolean pchVnextKeepAliveTimeWithoutCalls, ApacheFineract apacheFineract) throws IOException {
        //Set values required for the start stream call
        this.pchVnextFspId= pchVnextFspId; 
        this.pchVnextClientName = pchVnextClientName;
        this.apacheFineract = apacheFineract;
        //Prepare the TLS secure connection channel
        TlsChannelCredentials.Builder tlsBuilder = TlsChannelCredentials.newBuilder();
        tlsBuilder.trustManager(new File(pchVnextServerCertificate));
        //Create the Grpc connection channel using the parameters
        this.channel = Grpc.newChannelBuilderForAddress(pchVnextServerDNS, pchVnextServerPort, tlsBuilder.build())
                .keepAliveTime(pchVnextKeepAliveTime, TimeUnit.MILLISECONDS)
                .keepAliveTimeout(pchVnextKeepAliveTimeout, TimeUnit.MINUTES)
                .keepAliveWithoutCalls(pchVnextKeepAliveTimeWithoutCalls)
                .build();        
        //Prepare the headers required for the stream calls
        ClientInterceptor interceptor = new HeaderClientInterceptor(pchVnextAccessToken, pchVnextFspId);        
        //Create the custom Grpc channel
        this.channelWithHeader = ClientInterceptors.intercept(channel, interceptor);        
        //Create the non blockin stub instance
        connectionToVnext = InteropGrpcApiGrpc.newStub(channelWithHeader);  
        //Create the blockin stub instance
        connectionToBlockingVnext = InteropGrpcApiGrpc.newBlockingStub(channelWithHeader);
    }

    public void shutdown() throws InterruptedException {
        logger.info("Disconnecting vNext Client");
        channel.shutdown().awaitTermination(10, TimeUnit.SECONDS);
        logger.info("vNext Client Disconnected");
    }

    public boolean start() {
        //Prepare the initial message
        StreamFromClientMsg initialMessage =  StreamFromClientMsg.newBuilder()
                        .setInitialRequest(StreamClientInitialRequest.newBuilder()
                                .setFspId(this.pchVnextFspId)
                                .setClientName(this.pchVnextClientName).build()).build();
        //Prepare the initial streamm call object
        StreamObserver<StreamToClientMsg> responseObserver = new StreamObserver<StreamToClientMsg>() {            
            @Override
            public void onNext(StreamToClientMsg streamToClientMsg) {
                //Depending on the message type received we proccess it
                switch (streamToClientMsg.getResponseTypeCase()) {                    
                    case PARTYINFOREQUEST:
                        //Look up the information of the beneficiary
                        logger.debug("Processing PARTYINFOREQUEST");
                        sendPartyInfo(streamToClientMsg);                        
                        break;
                    case ACCEPTTRANSFERREQUEST:
                        //Execute the Money Transfer
                        logger.debug("Processing ACCEPTTRANSFERREQUEST");
                        sendMoneyTransfer(streamToClientMsg);
                        break;
                    case INITIALRESPONSE:
                        //Execute the Initial Connection only one time
                        logger.debug("Processing INITIALRESPONSE");                            
                        logger.debug("vNext Client is already initialized "+streamToClientMsg.getInitialResponse().isInitialized()); 
                        if(streamToClientMsg.getInitialResponse().isInitialized())
                            break;
                    default:
                        //Print a message when receiving a not supported message
                        logger.info("Message type not supported: " + streamToClientMsg.getResponseTypeCase());                        
                }
            }
            @Override
            public void onCompleted() {
                logger.debug("vNext Client stream completed");                
            }
            @Override
            public void onError(Throwable t) {
                logger.error("vNext Client stream error: "+t.getMessage());   
            }
        };        
        //Execute the initial stream
        streamFromClientMessageObserver = connectionToVnext.startStream(responseObserver);        
        try {
            //Send the initial message to the stream
            streamFromClientMessageObserver.onNext(initialMessage);            
        } catch (StatusRuntimeException e) {
            //Error received while sending the initial message
            logger.error("vNext Client Initial Connection failed with status:" + e.getStatus() + " message:" + e.getMessage());
            //Return the non successful status
            return false;
        }
        //vNext Grcp Client Connected and initialized 
        logger.info("******************************************************");        
        logger.info("* vNext Client Connected and Initialized Successfuly *");
        logger.info("******************************************************");        
        this.Loggined = true;
        //Return the successful status
        return true;
    }
    
    private void sendMoneyTransfer(StreamToClientMsg streamToClientMsg) {
        //Verify that the Stream is connected and initialized
        if (streamFromClientMessageObserver == null) {
            logger.error("vNext Client Not Connected");
            throw new IllegalStateException("vNext Client Not Connected.");
        }        
        try{
            //Prepare the Money Transfer Message        
            StreamFromClientMsg strmFromClient = handleTransferRequest(streamToClientMsg.getAcceptTransferRequest());                                                        
            //Send the Money Transfer Message Response to the Stream
            sendResponseMessage(strmFromClient);
        }
        catch(Exception e){
            //Print the error received when sending the Money Transfer Message Response to the Stream
            logger.error("ERROR "+  e.getMessage());
        }
    }
    
    public StreamFromClientMsg handleTransferRequest(ServerAcceptTransferRequest request) throws Exception {       
        
        ServerPartyInfoRequest serverPartyInfoRequest = ServerPartyInfoRequest.newBuilder()
                                                            .setPartyId(request.getTo().getIdValue())
                                                            .setDestinationFspId(request.getTo().getFspId())
                                                            .build();
        AccountLookupServiceResponse accountLookupResponse = apacheFineract.findClientAccount(serverPartyInfoRequest);
        AccountDepositServiceResponse transferFineractResponse = apacheFineract.depositToClientAccount(request, accountLookupResponse);
        //Build the response with the Transfer request information
        ServerAcceptTransferResponse.Builder serverAcceptTransferResponse = ServerAcceptTransferResponse.newBuilder();
        serverAcceptTransferResponse
                    .setTransferId(request.getTransferId())
                    .setRequestId(request.getRequestId())
                    .setDestinationFspId(request.getFrom().getFspId())
                    .setSourceFspId(request.getTo().getFspId())
                    .setHomeTransactionId(request.getHomeTransactionId())                                        
                    .build();        
        logger.debug("Final response: \n"+ serverAcceptTransferResponse);
        //Build the stream from client message
        StreamFromClientMsg transferResponse = StreamFromClientMsg.newBuilder()
                                            .setAcceptTransferResponse(serverAcceptTransferResponse)
                                            .build();
        //Return the stream from client message
        return transferResponse;        
    }
    
    private void sendPartyInfo(StreamToClientMsg streamToClientMsg) {
        //Verify that the Stream is connected and initialized
        if (streamFromClientMessageObserver == null) {
            logger.error("vNext Client Not Connected");
            throw new IllegalStateException("vNext Client Not Connected");
        }        
        try{
            //Prepare the Party Information Message        
            StreamFromClientMsg strmFromClient = handlePartyInfoRequest(streamToClientMsg.getPartyInfoRequest());        
            //Send the Party Information Message Response to the Stream
            sendResponseMessage(strmFromClient);
        }
        catch(Exception e){
            //Print the error received when sending the Party Information Message Response to the Stream
            logger.error("ERROR "+  e.getMessage());
        }
    }
    
    public StreamFromClientMsg handlePartyInfoRequest(ServerPartyInfoRequest request) throws Exception {
        //Call the Apache Fineract Rest Client       

        AccountLookupServiceResponse accountLookupResponse = apacheFineract.findClientAccount(request);
        
        //Build the response with the Party Info request information        
        LookupPartyResponse.Builder responseBuilder = LookupPartyResponse.newBuilder();
        // Build the message response with account information        
        LookupPartySuccessResponse successResponse = LookupPartySuccessResponse.newBuilder()
                                                        .setPartyId(request.getPartyId())
                                                        .setPartyIdType(request.getPartyIdType())
                                                        .setFirstName(accountLookupResponse.getFirstName())
                                                        .setLastName(accountLookupResponse.getLastName())                
                                                        .build();
        responseBuilder
                    .setSourceFspId(request.getDestinationFspId())
                    .setDestinationFspId(request.getSourceFspId())
                    .setRequestId(request.getPendingRequestId())
                    .setResponse(successResponse);        
        LookupPartyResponse response = responseBuilder.build();
        logger.debug("Final response built:  \n"+ response);
        //Build the stream from client message
        StreamFromClientMsg partyInfoResponse = StreamFromClientMsg.newBuilder()
                                            .setLookupPartyInfoResponse(response)
                                            .build();
        //Return the stream from client message
        return partyInfoResponse;        
    }

    public void sendResponseMessage(StreamFromClientMsg strmFromClient) throws InterruptedException {
        //Verify the response type for proper response
        logger.debug("Sending message response type "+strmFromClient.getRequestTypeCase());
        if("SHUTDOWN".equals(strmFromClient.getRequestTypeCase())){
            //Shutdown message received
            this.streamFromClientMessageObserver.onCompleted();
            this.Loggined = false;
            shutdown();
        }
        else{            
            //Send the response message to the stream
            if(this.streamFromClientMessageObserver != null) {                
                this.streamFromClientMessageObserver.onNext(strmFromClient);                
            }                
        }        
    }
    
    public PartyResponseDto getPartyInfo(PartyRequestDto partyRequest) {        
        //Verify if the vNext client has been connected    
        if (!this.Loggined) {
            logger.error("vNext Client not initialized yet." );
            throw new IllegalStateException("vNext Client not initialized yet.");            
        }
        //Prepare and setup the lookup request
        LookupPartyRequest grpcRequest = LookupPartyRequest.newBuilder()
                .setPartyId(partyRequest.getPartyId())
                .setPartyIdType(partyRequest.getPartyIdType())
                .setCurrencyCode(partyRequest.getCurrencyCode())
                .setOwnerFspId(partyRequest.getOwnerFspId())
                .build();        
        //Prepare the lookup response
        LookupPartyResponse grpcResponse = LookupPartyResponse.newBuilder().build();
        PartyResponseDto partyResponse = new PartyResponseDto();        
        try {         
            //Execute the lookup party information
            grpcResponse = this.connectionToBlockingVnext.lookupParty(grpcRequest);            
            //Fill the Lookup party information response 
            partyResponse.setTransactionId(grpcResponse.getRequestId());
            partyResponse.setCurrencyCode(grpcResponse.getResponse().getCurrencyCode());
            partyResponse.setDestinationFspId(grpcResponse.getDestinationFspId());
            partyResponse.setSourceFspId(grpcResponse.getSourceFspId());
            partyResponse.setPartyId(grpcResponse.getResponse().getPartyId());
            partyResponse.setPartyIdType(grpcResponse.getResponse().getPartyIdType());
            partyResponse.setFirsName(grpcResponse.getResponse().getFirstName());
            partyResponse.setMiddleName(grpcResponse.getResponse().getMiddleName());
            partyResponse.setLastName(grpcResponse.getResponse().getLastName());                                
            partyResponse.setOfficeName("EXTERNAL");
            partyResponse.setAccountType("SAVINGS");
            partyResponse.setExecutionStatus(true);
            partyResponse.setSystemMessage("success");
        } 
        catch (Exception e) {
            //Print the error message
            logger.error("PARTYINFOREQUEST failure: "+ e.getMessage());
            //Fill the Lookup party information response 
            partyResponse.setExecutionStatus(false);
            partyResponse.setSystemMessage(e.getMessage());
        }        
        return partyResponse;
    }
    
    public TransferResponseDto executeTransfer(TransferRequestDto transferRequest) {
        //Verify if the vNext client has been connected    
        if (!this.Loggined) {
            logger.error("vNext Client not initialized yet." );
            throw new IllegalStateException("vNext Client not initialized yet.");            
        }
        //Prepare and setup the Accept Transfer Request
        TransferRequest executeTransferRequest = TransferRequest.newBuilder()
                .setHomeTransactionId(transferRequest.getHomeTransactionId())
                .setFrom(VNextClientMapper.mapToParty(transferRequest.getFrom()))
                .setTo(VNextClientMapper.mapToParty(transferRequest.getTo()))
                .setAmountType(transferRequest.getAmountType())
                .setAmount(VNextClientMapper.mapToAmount(transferRequest.getAmount()))
                .setTransactionType(VNextClientMapper.mapToTransactionType(transferRequest.getTransactionType()))
                .setNote(transferRequest.getNote())
                .build();
        //Prepare the Accept Transfer Response
        TransferResponse grpcResponse = TransferResponse.newBuilder().build();
        TransferResponseDto transferResponse = new TransferResponseDto();        
        try {         
            //Execute the Accept Transfer Response 
            grpcResponse = this.connectionToBlockingVnext.executeTransfer(executeTransferRequest);
            //Fill the Accept Transfer Response 
            transferResponse.setHomeTransactionId(grpcResponse.getHomeTransactionId());
            transferResponse.setTransactionId(grpcResponse.getSuccess().getTransferId());
            transferResponse.setExecutionStatus(true);
            transferResponse.setSystemMessage("success");
        } 
        catch (Exception e) {
            //Print the error message
            logger.error("ACCEPTTRANSFERREQUEST failure: "+ e.getMessage());
            //Fill the Lookup party information response 
            transferResponse.setExecutionStatus(false);
            transferResponse.setSystemMessage(e.getMessage());
        }        
        return transferResponse;
    }    
    
    public ParticipantResponse getParticipant(ParticipantRequest participantRequest){
        //Verify if the vNext client has been connected    
        if (!this.Loggined) {
            logger.error("vNext Client not initialized yet." );
            throw new IllegalStateException("vNext Client not initialized yet.");            
        }

        LookupParticipantRequest lookupParticipantRequest = LookupParticipantRequest.newBuilder()
                .setPartyId(participantRequest.getPartyId())
                .setPartyIdType(participantRequest.getPartyIdType())
                .setCurrencyCode(participantRequest.getCurrencyCode())
                .build();
        
        LookupParticipantResponse lookupParticipantResponse = LookupParticipantResponse.newBuilder().build();
        ParticipantResponse participantResponse = new ParticipantResponse();
        
        try {         
            //Execute the Participant Query
            lookupParticipantResponse = this.connectionToBlockingVnext.lookupParticipant(lookupParticipantRequest);            
            //Fill the Participant Response 
            participantResponse.setFspId(lookupParticipantResponse.toString().split("\"")[1]);
            participantResponse.setPartyId(participantRequest.getPartyId());
            participantResponse.setExecutionStatus(true);
            participantResponse.setSystemMessage("success");
        } 
        catch (Exception e) {
            //Print the error message
            logger.error("PARTICIPANTREQUEST failure: "+ e.getMessage());
            //Fill the Lookup party information response 
            participantResponse.setExecutionStatus(false);
            participantResponse.setSystemMessage(e.getMessage());
        }        
        return participantResponse;
        
    }
}