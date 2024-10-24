/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mx.fintecheando.grpc.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class StreamFromClientMsgResponse {
    int requestTypeCase;
    int requestType;
}
