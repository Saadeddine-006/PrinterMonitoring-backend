package com.snmp.PrinterMonitoring.security;

import com.snmp.PrinterMonitoring.services.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // IMPORTANT: Removed "/api/auth/" from here.
    // Only truly public URL prefixes that don't need any authentication or specific exact match
    private static final List<String> PUBLIC_PREFIXES = Arrays.asList(
            "/favicon.ico",
            "/error",
            "/swagger-ui/",
            "/v3/api-docs/",
            "/api-docs/",
            "/actuator/health"
    );

    // Exact match endpoints that are completely public (e.g., login, register)
    private static final Set<String> PUBLIC_EXACT_MATCH_ENDPOINTS = new HashSet<>(Arrays.asList(
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/refresh"
            // '/api/auth/me' is NOT included here, as it requires authentication
    ));

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        log.info(">>>> JwtAuthenticationFilter: My unique version 3.0 is running and processing request <<<<");

        final String requestPath = request.getRequestURI();
        final String authHeader = request.getHeader("Authorization");

        log.info("DEBUG: Request URI: '{}'", requestPath);
        log.info("DEBUG: Public Prefixes configured: {}", PUBLIC_PREFIXES);
        log.info("DEBUG: Public Exact Match Endpoints configured: {}", PUBLIC_EXACT_MATCH_ENDPOINTS);

        // Check if the current request path is explicitly marked as public
        if (isPublicEndpoint(requestPath)) {
            log.info("Public endpoint detected: '{}'. Skipping JWT filter.", requestPath);
            filterChain.doFilter(request, response);
            return;
        }

        // If not a public endpoint, proceed with JWT processing
        log.info("DEBUG: Authorization Header received: '{}'", (authHeader != null ? authHeader : "NULL"));

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header for secure endpoint: {}. Header was: '{}'", requestPath, authHeader);
            // For a secured endpoint, if the header is missing/invalid, you might want to send a 401 Unauthorized
            // instead of just continuing the filter chain.
            // However, the current setup will let it pass and let Spring Security's
            // AuthorizationFilter or controller handle the lack of authentication.
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        log.info("DEBUG: Extracted JWT (first 10 chars): '{}'", jwt.length() > 10 ? jwt.substring(0, 10) + "..." : jwt);
        log.info("DEBUG: Extracted JWT length: {}", jwt.length());

        try {
            final String userEmail = jwtUtil.extractEmail(jwt);

            // Only attempt to authenticate if userEmail is found and no authentication is currently in context
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

                // Validate the token against the user details
                if (jwtUtil.validateToken(jwt, userDetails.getUsername())) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null, // credentials are null as token is already validated
                            userDetails.getAuthorities() // User roles/authorities
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // Set the authentication in Spring Security Context
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.debug("Authenticated user: {}", userEmail);
                } else {
                    log.warn("Invalid JWT token for user: {}", userEmail);
                    // Optionally, clear context or send 401 if token is invalid
                    SecurityContextHolder.clearContext();
                }
            } else if (userEmail == null) {
                log.warn("No email extracted from JWT or JWT is invalid for path: {}", requestPath);
                SecurityContextHolder.clearContext(); // Ensure no partial auth
            }
        } catch (Exception e) {
            log.error("JWT processing error for request {}: {}. Token might be expired or malformed.", requestPath, e.getMessage(), e);
            SecurityContextHolder.clearContext(); // Clear context on any JWT parsing/validation error
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(String requestPath) {
        log.debug("Inside isPublicEndpoint for: '{}'", requestPath);

        // Check for exact public matches first
        if (PUBLIC_EXACT_MATCH_ENDPOINTS.contains(requestPath)) {
            log.debug("'{}' is in PUBLIC_EXACT_MATCH_ENDPOINTS.", requestPath);
            return true;
        }

        // Then check for public prefixes
        boolean isPrefixMatch = PUBLIC_PREFIXES.stream().anyMatch(publicPath -> {
            boolean match = requestPath.startsWith(publicPath);
            if (match) {
                log.debug("'{}' starts with public prefix: '{}'", requestPath, publicPath);
            }
            return match;
        });

        if (isPrefixMatch) {
            return true;
        }

        log.debug("'{}' is NOT a public endpoint, proceeding with JWT filter.", requestPath);
        return false;
    }
}
