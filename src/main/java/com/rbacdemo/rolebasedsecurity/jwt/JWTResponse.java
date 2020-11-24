package com.rbacdemo.rolebasedsecurity.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class JWTResponse {

    private String jwtToken;

    private String username;

    private List<GrantedAuthority> roles;
}
