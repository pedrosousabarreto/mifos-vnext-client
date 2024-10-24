package com.mx.fintcheando.grpc.service.fineract;

import com.fasterxml.jackson.databind.JsonNode;
import com.mx.fintecheando.grpc.client.FineractClient;
import com.mx.fintecheando.grpc.proto.fineract.AccountLookupServiceGrpc;
import com.mx.fintecheando.grpc.proto.fineract.AccountLookupServiceRequest;
import com.mx.fintecheando.grpc.proto.fineract.AccountLookupServiceResponse;
import io.grpc.stub.StreamObserver;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.quarkus.grpc.GrpcService;
import jakarta.inject.Singleton;

@GrpcService
public class AccountLookupServiceGrpcImpl extends AccountLookupServiceGrpc.AccountLookupServiceImplBase {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccountLookupServiceGrpcImpl.class);

    @RestClient
    FineractClient fineractClient;

    @Override
    public void findClientAccount(AccountLookupServiceRequest request, StreamObserver<AccountLookupServiceResponse> responseObserver) {
        String account = request.getAccount();
        try {
            // Use the Quarkus REST Client to call the Fineract API
            JsonNode accountDetails = fineractClient.findClientAccount(account);
            AccountLookupServiceResponse response = AccountLookupServiceResponse.newBuilder()
                    .setAccountDetails(accountDetails.toString())
                    .build();
            responseObserver.onNext(response);
        } catch (Exception e) {
            LOGGER.error("Error fetching account details", e);
            responseObserver.onError(e);
        }
        responseObserver.onCompleted();
    }

    @Override
    public void findQuickClientAccount(AccountLookupServiceRequest request, StreamObserver<AccountLookupServiceResponse> responseObserver) {
        String account = request.getAccount();
        try {
            JsonNode quickAccountDetails = fineractClient.getAccountDetails(account);
            AccountLookupServiceResponse response = AccountLookupServiceResponse.newBuilder()
                    .setAccountDetails(quickAccountDetails.toString())
                    .build();
            responseObserver.onNext(response);
        } catch (Exception e) {
            LOGGER.error("Error fetching quick account details", e);
            responseObserver.onError(e);
        }
        responseObserver.onCompleted();
    }
}
