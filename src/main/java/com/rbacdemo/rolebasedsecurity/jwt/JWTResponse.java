package com.rbacdemo.rolebasedsecurity.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class JWTResponse {

    private String jwtToken;

    private String username;
}
