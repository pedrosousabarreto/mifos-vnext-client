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
package org.mifos.vnext.connector.rest.client;

import com.mx.fintecheando.grpc.proto.vnext.Amount;
import com.mx.fintecheando.grpc.proto.vnext.Party;
import com.mx.fintecheando.grpc.proto.vnext.TransactionType;
import org.mifos.vnext.connector.dto.AmountDto;
import org.mifos.vnext.connector.dto.PartyDto;
import org.mifos.vnext.connector.dto.TransactionTypeDto;

public class VNextClientMapper {
    public static Party mapToParty(PartyDto dto) {
        return Party.newBuilder()
                .setFspId(dto.getFspId())
                .setIdType(dto.getIdType())
                .setIdValue(dto.getIdValue())
                .setType(dto.getType() != null ? dto.getType() : "")
                .build();
    }

    public static Amount mapToAmount(AmountDto dto) {
        return Amount.newBuilder()
                .setCurrencyCode(dto.getCurrencyCode())
                .setAmount(dto.getAmount())
                .build();
    }

    public static TransactionType mapToTransactionType(TransactionTypeDto dto) {
        return TransactionType.newBuilder()
                .setScenario(dto.getScenario())
                .setSubScenario(dto.getSubScenario())
                .setInitiator(dto.getInitiator())
                .setInitiatorType(dto.getInitiatorType())
                .build();
    }
}
