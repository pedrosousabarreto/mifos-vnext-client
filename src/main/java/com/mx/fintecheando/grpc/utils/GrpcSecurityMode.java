/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mx.fintecheando.grpc.utils;


public enum GrpcSecurityMode {
    
    INSECURE (1){
        @Override
        public boolean isEnabled() {
            return true;
        }
    },
    SERVER_TLS (2){
        @Override
        public boolean isEnabled() {
            return true;
        }
    },
    MUTUAL_TLS (3){
        @Override
        public boolean isEnabled() {
            return true;
        }
    };

    public boolean isEnabled() {return false;}
    private final int securityType;
    
    private GrpcSecurityMode (int securityType) {
        this.securityType = securityType;
    }
}
