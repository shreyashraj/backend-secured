package com.natech.backendsecured.repository;

import com.natech.backendsecured.model.ApplicationUser;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;


@Repository
public interface ApplicationUserRepository extends MongoRepository<ApplicationUser, String> {
    Optional<ApplicationUser> findByUsername(String username);
}