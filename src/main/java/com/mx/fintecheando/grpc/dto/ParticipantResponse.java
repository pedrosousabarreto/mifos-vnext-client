package com.mx.fintecheando.grpc.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ParticipantResponse {
    String partyId;
    String partyIdType;
    String partySubIdOrType;
    String currencyCode;
}
