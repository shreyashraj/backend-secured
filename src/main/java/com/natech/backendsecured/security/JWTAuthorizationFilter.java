package com.natech.backendsecured.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.natech.backendsecured.service.UserDetailsServiceImpl;
import com.natech.backendsecured.utils.JwtUtil;
import com.natech.backendsecured.utils.SecurityConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

import static com.natech.backendsecured.utils.SecurityConstants.*;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private JwtUtil jwtUtil;

    private UserDetailsServiceImpl userDetailsService;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, UserDetailsServiceImpl userDetailsService, JwtUtil jwtUtil) {
        super(authenticationManager);
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(HEADER_STRING);

        if(header == null || !header.startsWith(TOKEN_PREFIX)){
            chain.doFilter(request,response);
            return;
        }

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = getAuthentication(request);
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        chain.doFilter(request,response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader(HEADER_STRING);
        if(token != null){
            String user = jwtUtil.extractUsername(token.replace(TOKEN_PREFIX,""));
            if(user != null){
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(user);
                if(jwtUtil.validateToken(token.replace(TOKEN_PREFIX,""), userDetails))
                    return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            }
            return null;
        }
        return null;
    }
}
