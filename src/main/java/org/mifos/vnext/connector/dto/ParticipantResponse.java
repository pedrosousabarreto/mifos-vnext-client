package org.mifos.vnext.connector.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ParticipantResponse {
    String partyId;
    String fspId;    
    boolean executionStatus;
    String systemMessage;
}
