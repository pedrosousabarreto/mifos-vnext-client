/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mx.fintecheando.grpc.controller;

import static java.util.Arrays.asList;

import java.util.HashMap;
import java.util.Map;

import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;


public class IncomingInterceptor implements ServerInterceptor {

    public static final Metadata.Key<String> EXTRA_HEADER = Metadata.Key.of("my-extra-header",
            Metadata.ASCII_STRING_MARSHALLER);
    public static final Metadata.Key<String> INTERFACE_HEADER = Metadata.Key.of("my-interface-header",
            Metadata.ASCII_STRING_MARSHALLER);
    public static final Metadata.Key<String> EXTRA_BLOCKING_HEADER = Metadata.Key.of("my-blocking-header",
            Metadata.ASCII_STRING_MARSHALLER);
    
    public static final Metadata.Key<String> GRPC_METADATA_TOKEN_FIELD_KEY = Metadata.Key.of("accessToken",
            Metadata.ASCII_STRING_MARSHALLER);
    
    public static final Metadata.Key<String> GRPC_METADATA_FSPID_FIELD_KEY = Metadata.Key.of("fspId",
            Metadata.ASCII_STRING_MARSHALLER);

    private final Map<String, String> headerValues = new HashMap<>();

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> serverCall, Metadata metadata,
            ServerCallHandler<ReqT, RespT> serverCallHandler) {

        for (Metadata.Key<String> key : asList(EXTRA_HEADER, INTERFACE_HEADER, EXTRA_BLOCKING_HEADER,GRPC_METADATA_TOKEN_FIELD_KEY,GRPC_METADATA_FSPID_FIELD_KEY)) {
            String header = metadata.get(key);
            if (header != null) {
                headerValues.put(key.name(), header);
            }
        }

        return serverCallHandler.startCall(serverCall, metadata);
    }

    public void clear() {
        headerValues.clear();
    }

    public Map<String, String> getCollectedHeaders() {
        return headerValues;
    }
}