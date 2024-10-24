package com.mx.fintecheando.grpc.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class ParticipantRequest {
    String partyId;
    String partyIdType;
    String partySubIdOrType;
    String currencyCode;
}
