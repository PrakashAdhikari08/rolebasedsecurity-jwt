package com.rbacdemo.rolebasedsecurity.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class JWTRequest {

    private String username;

    private String password;
}
