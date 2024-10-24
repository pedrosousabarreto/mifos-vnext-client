package com.mx.fintecheando.grpc.utils;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GrpcSecurityOptions {
    
    public GrpcSecurityMode Mode;
    public String CaCertFilePath;
    public String PrivateKeyFilePath;
    public String CertChainFilePath;
    
}
