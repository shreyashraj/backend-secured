package com.natech.backendsecured.service;

import com.natech.backendsecured.model.ApplicationUser;
import com.natech.backendsecured.model.MyUserDetails;
import com.natech.backendsecured.repository.ApplicationUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.management.relation.Role;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private ApplicationUserRepository applicationUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<ApplicationUser> applicationUser = applicationUserRepository.findByUsername(username);
        applicationUser.orElseThrow(() -> new UsernameNotFoundException("Not Found"+ username));
        return applicationUser.map(MyUserDetails::new).get();
    }
}
