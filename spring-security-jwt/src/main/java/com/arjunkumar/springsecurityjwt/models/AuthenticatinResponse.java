package com.arjunkumar.springsecurityjwt.models;

public class AuthenticatinResponse {
    private final String  jwt;

    public AuthenticatinResponse(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }
}
