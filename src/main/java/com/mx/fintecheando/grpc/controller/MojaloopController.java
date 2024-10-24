package com.mx.fintecheando.grpc.controller;

import static com.mx.fintecheando.grpc.controller.IncomingInterceptor.GRPC_METADATA_TOKEN_FIELD_KEY;

import java.util.concurrent.CompletionStage;

import static com.mx.fintecheando.grpc.controller.IncomingInterceptor.GRPC_METADATA_FSPID_FIELD_KEY;
import com.mx.fintecheando.grpc.dto.ParticipantRequest;
import com.mx.fintecheando.grpc.dto.ParticipantResponse;
import com.mx.fintecheando.grpc.dto.StreamFromClientMsgResponse;
import com.mx.fintecheando.grpc.proto.mojaloop.InteropGrpcApi;
import com.mx.fintecheando.grpc.proto.mojaloop.StreamFromClientMsg;

import io.quarkus.grpc.GrpcClient;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import com.mx.fintecheando.grpc.mapper.ParticipantMapper;
import io.grpc.Metadata;
import io.quarkus.grpc.GrpcClientUtils;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;

@Path("/mojaloop")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class MojaloopController {

    @GrpcClient("InteropGrpcApi")
    InteropGrpcApi interopGrpcApi;
    
    @Inject
    ParticipantMapper mapper;
    
    
    @POST
    @Path("/startStream")
    public void startStream(StreamFromClientMsg streamFromClientMsg) {
        // Crea un Multi a partir del mensaje recibido
    	
    	
        Multi<StreamFromClientMsg> multi = Multi.createFrom().item(streamFromClientMsg);

        // Iniciar el stream
        interopGrpcApi.startStream(multi)
            .subscribe().with(
                streamToClientMsg -> {
                    // Procesar cada mensaje recibido del stream
                    System.out.println("Received message from stream: " + streamToClientMsg);
                },
                failure -> {
                    // Error handling
                    System.err.println("Error during stream: " + failure.getMessage());
                }
            );
    }


    @POST
    @Path("/lookupparticipant")
    public Uni<ParticipantResponse> lookupParticipant(ParticipantRequest participantRequest, @QueryParam("headers") boolean headers) {
        Metadata extraHeaders = new Metadata();
        extraHeaders.put(GRPC_METADATA_TOKEN_FIELD_KEY, "");
        extraHeaders.put(GRPC_METADATA_FSPID_FIELD_KEY, "");
        
        InteropGrpcApi alteredInteropGrpcApi = GrpcClientUtils.attachHeaders(interopGrpcApi, extraHeaders); 
        StreamFromClientMsgResponse streamFromClientMsg = new StreamFromClientMsgResponse();

        
        return alteredInteropGrpcApi.lookupParticipant(mapper.participantRequestToLookupParticipantRequest(participantRequest)).map(mapper::lookupParticipantResponseToParticipantResponse);
    }
}