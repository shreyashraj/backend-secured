package com.natech.backendsecured.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/welcome")
    //@PreAuthorize("hasRole('ROLE_ADMIN')")
    public String admin(){
        return ("<h1>Welcome to Admin ! </h1>");
    }
}
