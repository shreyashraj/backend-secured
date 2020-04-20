package com.natech.backendsecured.utils;

public final class SecurityConstants {

    public static final String SECRET = "SecretKeyToGenJWTs";
    public static final long EXPIRATION_TIME = 864_000_000; // 10 days
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String ADMIN_SIGN_UP_URL = "/registration/admin-sign-up";
    public static final String USER_SIGN_UP_URL = "/registration/users-sign-up";


    public SecurityConstants() {
    }

}