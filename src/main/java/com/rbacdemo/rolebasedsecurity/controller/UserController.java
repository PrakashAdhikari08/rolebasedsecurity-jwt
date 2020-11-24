package com.rbacdemo.rolebasedsecurity.controller;


import com.rbacdemo.rolebasedsecurity.customService.CustomUserDetails;
import com.rbacdemo.rolebasedsecurity.customService.CustomUserDetailsService;
import com.rbacdemo.rolebasedsecurity.domain.User;
import com.rbacdemo.rolebasedsecurity.jwt.JWTRequest;
import com.rbacdemo.rolebasedsecurity.jwt.JWTResponse;
import com.rbacdemo.rolebasedsecurity.jwt.JWTUtility;
import com.rbacdemo.rolebasedsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/user/v1/")
public class UserController {

    public static final String DEFAULT_ROLE = "ROLE_USER";
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private JWTUtility jwtUtility;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @PostMapping("login")
    public JWTResponse loginUser(@RequestBody JWTRequest request) throws Exception {
    try {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getUsername(), request.getPassword()
        ));
    }
    catch (BadCredentialsException e){
        throw new Exception("INVALID_CREDENTIALS");
    }

    final UserDetails userDetails =
            customUserDetailsService.loadUserByUsername(request.getUsername());

    final String token = jwtUtility.generateToken(userDetails);

    return new JWTResponse(token,userDetails.getUsername());



    }

    @PostMapping("register")
    public String registerUser(@RequestBody User user) {
        String encodedPassword = bCryptPasswordEncoder.encode(user.getPassword());
        user.setRoles(DEFAULT_ROLE);
        user.setPassword(encodedPassword);
        userRepository.save(user);
        return "Welcome " + user.getUsername();
    }

    //if login User is admin then ==> can assign ADMIN or MOD
    //if login user is mod then ==>> only can assign MOD

    @GetMapping("access/{id}/{userRole}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_MOD')")
    public String giveAccessToUser(@PathVariable Integer id, @PathVariable String userRole, Principal principal){

        User user = userRepository.findById(id).get();
        List<String> activeRoles = getRolesByLoggedInUser(principal);
        String newRole ="";
        if(activeRoles.contains(userRole)){
            newRole = user.getRoles()+","+userRole;
            user.setRoles(newRole);
        }

        userRepository.save(user);
        return "HI "+ user.getUsername() + "New Role is assigned to you By " + principal.getName();

    }

    @GetMapping("all")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<User> users(){
        return userRepository.findAll();
    }


    @GetMapping("test")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String test(){
        return "Test END POINT!!";
    }



    private User getLoggedInUser(Principal principal){
        return userRepository.findByUsername(principal.getName()).get();
    }

    private List<String> getRolesByLoggedInUser(Principal principal){
        String roles = getLoggedInUser(principal).getRoles();
        List<String> assignedRoles = Arrays.stream(roles.split(",")).collect(Collectors.toList());

        if (assignedRoles.contains("ROLE_ADMIN")){
            return Arrays.asList(new String[]{"ROLE_ADMIN", "ROLE_MOD"});
        }

        if (assignedRoles.contains("ROLE_MOD")){
            return Arrays.asList(new String[]{"ROLE_MOD"});
        }

        return Collections.emptyList();
    }
}
