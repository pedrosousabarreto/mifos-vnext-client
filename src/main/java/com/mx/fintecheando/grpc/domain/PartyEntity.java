package com.mx.fintecheando.grpc.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@Entity
@Table(name = "PARTIES")
public class PartyEntity {
    @Id
    @SequenceGenerator(name = "parties_id_seq", allocationSize = 1, initialValue = 5)
    @GeneratedValue(generator = "parties_id_seq")
    private Long partyId;
    private Long partyIdType;
    private Long partySubIdOrType;
    private String currencyCode;
}