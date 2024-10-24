package com.mx.fintecheando.grpc.client;


import com.fasterxml.jackson.databind.JsonNode;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

@RegisterRestClient(baseUri = "https://elephant.mifos.community/fineract-provider/api/v1/")

@Path("/local-account")
public interface FineractClient {

    @GET
    @Path("/search/{account}")
    @Produces(MediaType.APPLICATION_JSON)
    JsonNode findClientAccount(@PathParam("account") String account);

    @GET
    @Path("/details/{accountNumber}")
    @Produces(MediaType.APPLICATION_JSON)
    JsonNode getAccountDetails(@PathParam("accountNumber") String accountNumber);
}

