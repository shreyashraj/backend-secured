package com.natech.backendsecured.model;

import org.springframework.data.annotation.Id;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;


public class ApplicationUser {
    @Id
    public String id;
    private String username;
    private String password;
    private boolean active;
    private String roles;

    public ApplicationUser() {
    }

    public ApplicationUser(String id, String username, String password, boolean active, String roles) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.active = active;
        this.roles = roles;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    public String getRoles() {
        return roles;
    }

    public void setRoles(String roles) {
        this.roles = roles;
    }
}
