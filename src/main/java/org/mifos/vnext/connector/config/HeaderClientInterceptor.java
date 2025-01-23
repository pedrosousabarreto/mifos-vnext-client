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
package org.mifos.vnext.connector.config;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientCall.Listener;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall.SimpleForwardingClientCall;
import io.grpc.ForwardingClientCallListener.SimpleForwardingClientCallListener;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class HeaderClientInterceptor implements ClientInterceptor {

    private final Logger logger = LoggerFactory.getLogger(HeaderClientInterceptor.class.getName());
    
    public static final Metadata.Key<String> GRPC_METADATA_TOKEN_FIELD_KEY = Metadata.Key.of("accessToken", Metadata.ASCII_STRING_MARSHALLER);
    public static final Metadata.Key<String> GRPC_METADATA_FSPID_FIELD_KEY = Metadata.Key.of("fspId", Metadata.ASCII_STRING_MARSHALLER);
    private final String pchAccessToken; 
    private final String pchFspId;
    
    public HeaderClientInterceptor(String pchVnextAccessToken, String pchVnextFspId){
        this.pchAccessToken = pchVnextAccessToken;
        this.pchFspId = pchVnextFspId;
    }
    
    @Override
    public < ReqT, RespT > ClientCall < ReqT, RespT > interceptCall(MethodDescriptor < ReqT, RespT > method,
        CallOptions callOptions, Channel next) {
        return new SimpleForwardingClientCall < ReqT, RespT > (next.newCall(method, callOptions)) {
            @Override
            public void start(Listener < RespT > responseListener, Metadata headers) {
                /* put custom header */
                Metadata fixedHeaders = new Metadata();
                headers.put(GRPC_METADATA_TOKEN_FIELD_KEY, pchAccessToken);
                headers.put(GRPC_METADATA_FSPID_FIELD_KEY, pchFspId);
                headers.merge(fixedHeaders);
                super.start(new SimpleForwardingClientCallListener < RespT > (responseListener) {
                    @Override
                    public void onHeaders(Metadata headers) {
                        /**
                         * if you don't need receive header from server,
                         * you can use {@link io.grpc.stub.MetadataUtils attachHeaders}
                         * directly to send header
                         */
                        //logger.info("header received from server:" + headers.toString());
                        super.onHeaders(headers);
                    }
                }, headers);
            }
        };
    }
}