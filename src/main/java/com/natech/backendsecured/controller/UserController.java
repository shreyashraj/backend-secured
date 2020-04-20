package com.natech.backendsecured.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/welcome")
    //@PreAuthorize("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
    public String user(){
        return ("<h1>Welcome to User ! </h1>");
    }

}
