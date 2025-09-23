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

import io.grpc.netty.NettyChannelBuilder;
import org.mifos.grpc.proto.vnext.InteropGrpcApiGrpc;
import org.mifos.grpc.proto.vnext.LookupParticipantRequest;
import org.mifos.grpc.proto.vnext.LookupParticipantResponse;
import org.mifos.grpc.proto.vnext.LookupPartyRequest;
import org.mifos.grpc.proto.vnext.LookupPartyResponse;
import org.mifos.grpc.proto.vnext.LookupPartySuccessResponse;
import org.mifos.grpc.proto.vnext.ServerAcceptTransferRequest;
import org.mifos.grpc.proto.vnext.ServerAcceptTransferResponse;
import org.mifos.grpc.proto.vnext.ServerPartyInfoRequest;
import org.mifos.grpc.proto.vnext.StreamClientChallengeResponse;
import org.mifos.grpc.proto.vnext.StreamClientInitialRequest;
import org.mifos.grpc.proto.vnext.StreamFromClientMsg;
import org.mifos.grpc.proto.vnext.StreamServerInitialResponse;
import org.mifos.grpc.proto.vnext.StreamServerReadyResponse;
import org.mifos.grpc.proto.vnext.StreamToClientMsg;
import org.mifos.grpc.proto.vnext.TransferRequest;
import org.mifos.grpc.proto.vnext.TransferResponse;

import io.grpc.Channel;
import io.grpc.ClientInterceptors;
import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.mifos.vnext.connector.dto.AccountDepositServiceResponse;
import org.mifos.vnext.connector.dto.AccountLookupServiceResponse;
import org.mifos.vnext.connector.dto.AccountWithdrawalServiceResponse;
import org.mifos.vnext.connector.dto.ParticipantRequest;
import org.mifos.vnext.connector.dto.ParticipantResponse;
import org.mifos.vnext.connector.dto.PartyRequestDto;
import org.mifos.vnext.connector.dto.PartyResponseDto;
import org.mifos.vnext.connector.dto.TransferRequestDto;
import org.mifos.vnext.connector.dto.TransferResponseDto;
import org.mifos.vnext.connector.rest.client.ApacheFineract;
import org.mifos.vnext.connector.rest.client.VNextClientMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class VnextClient {

    private static final Logger logger = LoggerFactory.getLogger(VnextClient.class);

    private final ManagedChannel channel;
    private final Channel channelWithHeader;
    private final InteropGrpcApiGrpc.InteropGrpcApiStub connectionToVnext;
    private final InteropGrpcApiGrpc.InteropGrpcApiBlockingStub connectionToBlockingVnext;
    private StreamObserver<StreamFromClientMsg> streamFromClientMessageObserver;
    private boolean Loggined = false;
    private final String pchVnextFspId;
    private final String pchVnextClientName;
    private final ApacheFineract apacheFineract;

    // Nuevos campos para autenticación
    private final CryptoAndCertHelper cryptoHelper;
    private final HeaderClientInterceptor headerInterceptor;
    private final String clientId;
    private String sessionSecret;
    private final boolean mainClient;
    private final String pchVnextClientVersion;
    private final String clientCertificate;
    private final String clientPublicKeyPath;    
    private final String clientPrivateKeyPath;    
    private final String serverIntermediateCertificatePath;
    private final String serverRootCertificatePath;
    private final String serverFullCertPem;
    

    // Constantes de timeout
    private static final int DEFAULT_GRPC_CONNECT_TIMEOUT_MS = 5000;
    private static final int DEFAULT_GRPC_KEEPALIVE_TIME_MS = 10000;
    private static final int DEFAULT_GRPC_KEEPALIVE_TIMEOUT_MS = 5000;

    public VnextClient( String pchVnextFspId,
                        String pchVnextClientName, 
                        String pchVnextClientVersion,
                        String clientPrivateKeyPath, 
                        String clientPublicKeyPath,
                        String clientCertPath,
                        String serverIntermediateCertificatePath, 
                        String serverRootCertificatePath, 
                        String fullCertificate,
                        boolean mainClient, 
                        String pchVnextServerDNS,
                        int pchVnextServerPort,
                        int pchVnextKeepAliveTime, int pchVnextKeepAliveTimeout,
                        boolean pchVnextKeepAliveTimeWithoutCalls, ApacheFineract apacheFineract) throws Exception {

        // Almacenar parámetros
        this.pchVnextFspId = pchVnextFspId;
        this.pchVnextClientName = pchVnextClientName;
        this.pchVnextClientVersion = pchVnextClientVersion;
        this.apacheFineract = apacheFineract;
        this.mainClient = mainClient;
        //Client certificate and keys
        this.clientPublicKeyPath=clientPublicKeyPath;
        this.clientPrivateKeyPath=clientPrivateKeyPath;
        this.clientCertificate = loadClientCertPem(clientCertPath);
        //Server certificates
        this.serverIntermediateCertificatePath = serverIntermediateCertificatePath;
        this.serverRootCertificatePath = serverRootCertificatePath;
        this.serverFullCertPem=fullCertificate;
        
        // Inicializar crypto helper
        logger.info("Initializing CryptoAndCertHelper ");
        logger.info("Client Private Key: {} ", clientPrivateKeyPath);
        logger.info("Server Intermediate Certificate: {}", serverIntermediateCertificatePath);
        this.cryptoHelper = new CryptoAndCertHelper(clientPrivateKeyPath, serverIntermediateCertificatePath);

        // Generar client ID único
        this.clientId = UUID.randomUUID().toString();
        logger.info("Generated client ID for authentication: {}", clientId);

        // Usar valores por defecto si no se proporcionan
        int keepAliveTime = pchVnextKeepAliveTime > 0 ? pchVnextKeepAliveTime : DEFAULT_GRPC_KEEPALIVE_TIME_MS;
        int keepAliveTimeout = pchVnextKeepAliveTimeout > 0 ? pchVnextKeepAliveTimeout : DEFAULT_GRPC_KEEPALIVE_TIMEOUT_MS;

        // Crear el canal gRPC con SslContext de Netty
        try {


            logger.info("Creating secure gRPC channel to {}:{}", pchVnextServerDNS, pchVnextServerPort);            
            // Crear el canal
            this.channel = NettyChannelBuilder.forAddress(pchVnextServerDNS, pchVnextServerPort)                    
                    .keepAliveTime(keepAliveTime, TimeUnit.MILLISECONDS)
                    .keepAliveTimeout(keepAliveTimeout, TimeUnit.MILLISECONDS)
                    .keepAliveWithoutCalls(pchVnextKeepAliveTimeWithoutCalls)
                    .build();

            logger.info("gRPC channel created successfully");
        } catch (Exception e) {
            logger.error("Failed to create gRPC channel with Netty", e);
            throw new RuntimeException("Failed to create gRPC channel: " + e.getMessage(), e);
        }

        // Crear el interceptor y configurar clientId
        this.headerInterceptor = new HeaderClientInterceptor(pchVnextFspId);
        this.headerInterceptor.setClientId(this.clientId);

        // Crear el canal personalizado con headers
        this.channelWithHeader = ClientInterceptors.intercept(channel, headerInterceptor);

        // Crear los stubs
        connectionToVnext = InteropGrpcApiGrpc.newStub(channelWithHeader);
        connectionToBlockingVnext = InteropGrpcApiGrpc.newBlockingStub(channelWithHeader);

        logger.info("VnextClient initialized successfully for FSP: {}", pchVnextFspId);
    }

    public boolean start() {
        logger.info("Starting authentication process for client: {}", clientId);

        // Preparar mensaje inicial
        StreamClientInitialRequest initialRequest = StreamClientInitialRequest.newBuilder()
                .setFspId(this.pchVnextFspId)
                .setClientName(this.pchVnextClientName)
                .setClientVersion(this.pchVnextClientVersion)
                .setMainClient(this.mainClient)
                .setClientPem(this.clientCertificate)
                .build();

        StreamFromClientMsg initialMessage = StreamFromClientMsg.newBuilder()
                .setInitialRequest(initialRequest)
                .build();

        // Preparar el observer para respuestas del servidor
        StreamObserver<StreamToClientMsg> responseObserver = new StreamObserver<StreamToClientMsg>() {
            @Override
            public void onNext(StreamToClientMsg streamToClientMsg) {
                try {
                    switch (streamToClientMsg.getResponseTypeCase()) {
                        case INITIALRESPONSE:
                            logger.debug("Processing INITIALRESPONSE - Challenge received");
                            handleInitialResponse(streamToClientMsg.getInitialResponse());
                            break;
                        case READYRESPONSE:
                            logger.debug("Processing READYRESPONSE - Authentication complete");
                            handleReadyResponse(streamToClientMsg.getReadyResponse());
                            break;
                        case PARTYINFOREQUEST:
                            if (Loggined) {
                                logger.debug("Processing PARTYINFOREQUEST");
                                sendPartyInfo(streamToClientMsg);
                            } else {
                                logger.warn("Received party info request but client not authenticated");
                            }
                            break;
                        case ACCEPTTRANSFERREQUEST:
                            if (Loggined) {
                                logger.debug("Processing ACCEPTTRANSFERREQUEST");
                                sendMoneyTransfer(streamToClientMsg);
                            } else {
                                logger.warn("Received transfer request but client not authenticated");
                            }
                            break;
                        case STREAMMESSAGEERROR:
                            logger.error("Stream error received: {}",
                                    streamToClientMsg.getStreamMessageError().getMessage());
                            break;
                        default:
                            logger.debug("Received unhandled message type: {}",
                                    streamToClientMsg.getResponseTypeCase());
                    }
                } catch (Exception e) {
                    logger.error("Error processing server message: {}", e.getMessage(), e);
                }
            }

            @Override
            public void onCompleted() {
                logger.info("Server closed the stream");
                Loggined = false;
                sessionSecret = null;
                headerInterceptor.clearSession();
            }

            @Override
            public void onError(Throwable t) {
                logger.error("Stream error occurred", t);
                Loggined = false;
                sessionSecret = null;
                headerInterceptor.clearSession();
            }
        };

        try {
            streamFromClientMessageObserver = connectionToVnext.startStream(responseObserver);
            streamFromClientMessageObserver.onNext(initialMessage);
            logger.info("Authentication process started successfully for client: {}", clientId);
            return true;
        } catch (StatusRuntimeException e) {
            logger.error("Failed to start authentication - gRPC status: {}", e.getStatus(), e);
            return false;
        } catch (Exception e) {
            logger.error("Failed to start authentication", e);
            return false;
        }
    }

    private void handleInitialResponse(StreamServerInitialResponse response) {
        try {
            logger.debug("Validating server signature and processing challenge");
            logger.info("************************");
            logger.info("this.clientId "+this.clientId);
            logger.info("response.getSignedClientId() "+response.getSignedClientId());
            logger.info("response.getPubKeyFingerprint() "+response.getPubKeyFingerprint());
            logger.info("************************");
            // Validar firma del servidor
            boolean isValid = cryptoHelper.validateSignature(
                    this.clientId,
                    response
                    
            );
           
            if (!isValid) {
                logger.error("Invalid server signature received.");
                logger.error("Expected fingerprint: {} ", cryptoHelper.getServerIntermediatePublicKeyFingerprint());
                logger.error("Received: {} ", response.getPubKeyFingerprint());
                throw new SecurityException("Invalid server signature");
            }

            logger.info("Server signature validated successfully");

            // Firmar el challenge nonce
            String signedNonce = cryptoHelper.signString(response.getChallengeNonce());
            String clientPubKeyFingerprint = cryptoHelper.getServerIntermediatePublicKeyFingerprint();

            logger.debug("Challenge nonce signed successfully");

            // Enviar respuesta al challenge
            StreamClientChallengeResponse challengeResponse = StreamClientChallengeResponse.newBuilder()
                    .setSignedNonce(signedNonce)
                    .setPubKeyFingerprint(clientPubKeyFingerprint)
                    .build();

            StreamFromClientMsg responseMsg = StreamFromClientMsg.newBuilder()
                    .setChallengeResponse(challengeResponse)
                    .build();

            streamFromClientMessageObserver.onNext(responseMsg);
            logger.info("Challenge response sent to server successfully");

        } catch (Exception e) {
            logger.error("Error handling initial response: {}", e.getMessage(), e);
            try {
                if (streamFromClientMessageObserver != null) {
                    streamFromClientMessageObserver.onError(e);
                }
            } catch (Exception ex) {
                logger.error("Error closing stream after authentication failure", ex);
            }
        }
    }

    private void handleReadyResponse(StreamServerReadyResponse response) {
        this.sessionSecret = response.getSessionSecret();

        // Actualizar el interceptor con el session secret
        headerInterceptor.setSessionSecret(this.sessionSecret);

        this.Loggined = true;
        logger.info("Authentication complete. Session ready with secret for client: {}", clientId);
    }

    private String loadClientCertPem(String certFilePath) throws IOException {
        try {
            String certContent = new String(Files.readAllBytes(Paths.get(certFilePath)), StandardCharsets.UTF_8);
            logger.debug("Loaded client certificate from: {}", certFilePath);
            return certContent;
        } catch (IOException e) {
            logger.error("Failed to load client certificate from: {}", certFilePath, e);
            throw new IOException("Failed to load client certificate: " + e.getMessage(), e);
        }
    }

    private void checkAuthentication() {
        if (!this.Loggined || !headerInterceptor.isAuthenticated()) {
            throw new IllegalStateException("vNext Client not authenticated yet. Call start() first.");
        }
    }

    public void shutdown() throws InterruptedException {
        logger.info("Disconnecting vNext Client");
        this.Loggined = false;
        this.sessionSecret = null;
        headerInterceptor.clearSession();

        if (streamFromClientMessageObserver != null) {
            try {
                streamFromClientMessageObserver.onCompleted();
            } catch (Exception e) {
                logger.warn("Error completing stream: {}", e.getMessage());
            }
        }

        channel.shutdown().awaitTermination(10, TimeUnit.SECONDS);
        logger.info("vNext Client Disconnected");
    }

    private void sendMoneyTransfer(StreamToClientMsg streamToClientMsg) {
        checkAuthentication();

        if (streamFromClientMessageObserver == null) {
            logger.error("vNext Client Not Connected");
            throw new IllegalStateException("vNext Client Not Connected.");
        }

        try{
            StreamFromClientMsg strmFromClient = handleTransferRequest(streamToClientMsg.getAcceptTransferRequest());
            sendResponseMessage(strmFromClient);
        }
        catch(Exception e){
            logger.error("ERROR processing transfer request: {}", e.getMessage(), e);
        }
    }

    public StreamFromClientMsg handleTransferRequest(ServerAcceptTransferRequest request) throws Exception {
        checkAuthentication();

        ServerPartyInfoRequest serverPartyInfoRequest = ServerPartyInfoRequest.newBuilder()
                .setPartyId(request.getTo().getIdValue())
                .setDestinationFspId(request.getTo().getFspId())
                .build();
        AccountLookupServiceResponse accountLookupResponse = apacheFineract.findClientAccount(serverPartyInfoRequest);
        AccountDepositServiceResponse transferFineractResponse = apacheFineract.depositToClientAccount(request, accountLookupResponse);

        if(transferFineractResponse.getTransactionStatus().equalsIgnoreCase("success")){
            ServerPartyInfoRequest sourcePartyInfoRequest = ServerPartyInfoRequest.newBuilder()
                    .setPartyId(request.getFrom().getIdValue())
                    .setDestinationFspId(request.getFrom().getFspId())
                    .build();
            AccountLookupServiceResponse sourceAccountLookupResponse = apacheFineract.findClientAccount(sourcePartyInfoRequest);
            AccountWithdrawalServiceResponse withdrawalFineractResponse = apacheFineract.withdrawalFromClientAccount(request, sourceAccountLookupResponse);
        }

        ServerAcceptTransferResponse.Builder serverAcceptTransferResponse = ServerAcceptTransferResponse.newBuilder();
        serverAcceptTransferResponse
                .setTransferId(request.getTransferId())
                .setRequestId(request.getRequestId())
                .setDestinationFspId(request.getFrom().getFspId())
                .setSourceFspId(request.getTo().getFspId())
                .setHomeTransactionId(request.getHomeTransactionId())
                .build();

        logger.debug("Final transfer response built");

        return StreamFromClientMsg.newBuilder()
                .setAcceptTransferResponse(serverAcceptTransferResponse)
                .build();
    }

    private void sendPartyInfo(StreamToClientMsg streamToClientMsg) {
        checkAuthentication();

        if (streamFromClientMessageObserver == null) {
            logger.error("vNext Client Not Connected");
            throw new IllegalStateException("vNext Client Not Connected");
        }

        try{
            StreamFromClientMsg strmFromClient = handlePartyInfoRequest(streamToClientMsg.getPartyInfoRequest());
            sendResponseMessage(strmFromClient);
        }
        catch(Exception e){
            logger.error("ERROR processing party info request: {}", e.getMessage(), e);
        }
    }

    public StreamFromClientMsg handlePartyInfoRequest(ServerPartyInfoRequest request) throws Exception {
        checkAuthentication();

        AccountLookupServiceResponse accountLookupResponse = apacheFineract.findClientAccount(request);

        LookupPartyResponse.Builder responseBuilder = LookupPartyResponse.newBuilder();
        LookupPartySuccessResponse successResponse = LookupPartySuccessResponse.newBuilder()
                .setPartyId(request.getPartyId())
                .setPartyIdType(request.getPartyIdType())
                .setFirstName(accountLookupResponse.getFirstName())
                .setLastName(accountLookupResponse.getLastName())
                .build();
        responseBuilder
                .setSourceFspId(request.getDestinationFspId())
                .setDestinationFspId(request.getSourceFspId())
                .setResponse(successResponse);

        LookupPartyResponse response = responseBuilder.build();
        logger.debug("Party info response built");

        return StreamFromClientMsg.newBuilder()
                .setLookupPartyInfoResponse(response)
                .build();
    }

    public void sendResponseMessage(StreamFromClientMsg strmFromClient) throws InterruptedException {
        checkAuthentication();

        logger.debug("Sending message response type: {}", strmFromClient.getRequestTypeCase());

        if (this.streamFromClientMessageObserver != null) {
            this.streamFromClientMessageObserver.onNext(strmFromClient);
        }
    }

    public PartyResponseDto getPartyInfo(PartyRequestDto partyRequest) {
        checkAuthentication();

        LookupPartyRequest grpcRequest = LookupPartyRequest.newBuilder()
                .setPartyId(partyRequest.getPartyId())
                .setPartyIdType(partyRequest.getPartyIdType())
                .setCurrencyCode(partyRequest.getCurrencyCode())
                .setOwnerFspId(partyRequest.getOwnerFspId())
                .build();

        LookupPartyResponse grpcResponse = LookupPartyResponse.newBuilder().build();
        PartyResponseDto partyResponse = new PartyResponseDto();
        try {
            grpcResponse = this.connectionToBlockingVnext.lookupParty(grpcRequest);
            partyResponse.setTransactionId(grpcResponse.getRequestId());
            partyResponse.setCurrencyCode(grpcResponse.getResponse().getCurrencyCode());
            partyResponse.setDestinationFspId(grpcResponse.getDestinationFspId());
            partyResponse.setSourceFspId(grpcResponse.getSourceFspId());
            partyResponse.setPartyId(grpcResponse.getResponse().getPartyId());
            partyResponse.setPartyIdType(grpcResponse.getResponse().getPartyIdType());
            partyResponse.setFirsName(grpcResponse.getResponse().getFirstName());
            partyResponse.setMiddleName(grpcResponse.getResponse().getMiddleName());
            partyResponse.setLastName(grpcResponse.getResponse().getLastName());
            partyResponse.setExecutionStatus(true);
            partyResponse.setSystemMessage("success");
        }
        catch (Exception e) {
            logger.error("PARTYINFOREQUEST failure: {}", e.getMessage(), e);
            partyResponse.setExecutionStatus(false);
            partyResponse.setSystemMessage(e.getMessage());
        }
        return partyResponse;
    }

    public TransferResponseDto executeTransfer(TransferRequestDto transferRequest) {
        checkAuthentication();

        TransferRequest executeTransferRequest = TransferRequest.newBuilder()
                .setHomeTransactionId(transferRequest.getHomeTransactionId())
                .setFrom(VNextClientMapper.mapToParty(transferRequest.getFrom()))
                .setTo(VNextClientMapper.mapToParty(transferRequest.getTo()))
                .setAmountType(transferRequest.getAmountType())
                .setAmount(VNextClientMapper.mapToAmount(transferRequest.getAmount()))
                .setTransactionType(VNextClientMapper.mapToTransactionType(transferRequest.getTransactionType()))
                .setNote(transferRequest.getNote())
                .build();

        TransferResponse grpcResponse = TransferResponse.newBuilder().build();
        TransferResponseDto transferResponse = new TransferResponseDto();
        try {
            grpcResponse = this.connectionToBlockingVnext.executeTransfer(executeTransferRequest);
            transferResponse.setHomeTransactionId(grpcResponse.getHomeTransactionId());
            transferResponse.setTransactionId(grpcResponse.getSuccess().getTransferId());
            transferResponse.setExecutionStatus(true);
            transferResponse.setSystemMessage("success");
        }
        catch (Exception e) {
            logger.error("ACCEPTTRANSFERREQUEST failure: {}", e.getMessage(), e);
            transferResponse.setExecutionStatus(false);
            transferResponse.setSystemMessage(e.getMessage());
        }
        return transferResponse;
    }

    public ParticipantResponse getParticipant(ParticipantRequest participantRequest){
        checkAuthentication();

        LookupParticipantRequest lookupParticipantRequest = LookupParticipantRequest.newBuilder()
                .setPartyId(participantRequest.getPartyId())
                .setPartyIdType(participantRequest.getPartyIdType())
                .setCurrencyCode(participantRequest.getCurrencyCode())
                .build();

        LookupParticipantResponse lookupParticipantResponse = LookupParticipantResponse.newBuilder().build();
        ParticipantResponse participantResponse = new ParticipantResponse();

        try {
            lookupParticipantResponse = this.connectionToBlockingVnext.lookupParticipant(lookupParticipantRequest);
            participantResponse.setFspId(lookupParticipantResponse.toString().split("\"")[1]);
            participantResponse.setPartyId(participantRequest.getPartyId());
            participantResponse.setExecutionStatus(true);
            participantResponse.setSystemMessage("success");
        }
        catch (Exception e) {
            logger.error("PARTICIPANTREQUEST failure: {}", e.getMessage(), e);
            participantResponse.setExecutionStatus(false);
            participantResponse.setSystemMessage(e.getMessage());
        }
        return participantResponse;
    }

    // Getters para estado de autenticación
    public boolean isAuthenticated() {
        return Loggined && headerInterceptor.isAuthenticated();
    }

    public String getClientId() {
        return clientId;
    }

    public String getSessionSecret() {
        return sessionSecret;
    }

    // Método para reconexión
    public boolean reconnect() {
        try {
            shutdown();
            Thread.sleep(1000);
            return start();
        } catch (Exception e) {
            logger.error("Reconnection failed", e);
            return false;
        }
    }
}