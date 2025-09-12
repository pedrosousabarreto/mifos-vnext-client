package org.mifos.vnext.connector.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PartyDissociateRequestDto {
    String fspId;
    String partyId;
    String partyIdType;
    String partySubIdOrType;
    String currencyCode;
}
