package com.mx.fintecheando.grpc.mapper;


import com.mx.fintecheando.grpc.dto.ParticipantRequest;
import com.mx.fintecheando.grpc.dto.ParticipantResponse;
import com.mx.fintecheando.grpc.dto.StreamFromClientMsgResponse;
import com.mx.fintecheando.grpc.dto.StreamToClientMsgRequest;
import com.mx.fintecheando.grpc.proto.mojaloop.LookupParticipantRequest;
import com.mx.fintecheando.grpc.proto.mojaloop.LookupParticipantResponse;
import com.mx.fintecheando.grpc.proto.mojaloop.StreamFromClientMsg;
import com.mx.fintecheando.grpc.proto.mojaloop.StreamToClientMsg;
import org.mapstruct.Mapper;

@Mapper(componentModel = "cdi")
public interface ParticipantMapper {
    StreamToClientMsg streamToClientMsgRequest(StreamToClientMsgRequest streamToClientMsg);
    StreamFromClientMsg streamFromClientMsg(StreamFromClientMsgResponse streamFromClientMsg);
    StreamFromClientMsgResponse streamFromClientMsg(StreamFromClientMsg streamFromClientMsg);
    
    LookupParticipantRequest participantRequestToLookupParticipantRequest(ParticipantRequest participantRequest);
    ParticipantResponse lookupParticipantResponseToParticipantResponse(LookupParticipantResponse lookupParticipantResponse);
    
}