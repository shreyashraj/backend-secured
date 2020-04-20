package com.natech.backendsecured.controller;

import com.natech.backendsecured.model.ApplicationUser;
import com.natech.backendsecured.repository.ApplicationUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

@RestController
@RequestMapping("/registration")
public class ApplicationUserController {

    @Autowired
    private ApplicationUserRepository  applicationUserRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/users-sign-up")
    public void signUp(@RequestBody ApplicationUser user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        user.setActive(true);
        applicationUserRepository.save(user);
    }

    @PostMapping("/admin-sign-up")
    public void adminDignUp(@RequestBody ApplicationUser user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_ADMIN,ROLE_USER");
        user.setActive(true);
        applicationUserRepository.save(user);
    }
}
