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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.HashSet;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final List<String> PUBLIC_PREFIXES = Arrays.asList(
            "/favicon.ico",
            "/error",
            "/swagger-ui/",
            "/v3/api-docs/",
            "/api-docs/",
            "/actuator/health"
    );

    private static final Set<String> PUBLIC_EXACT_MATCH_ENDPOINTS = new HashSet<>(Arrays.asList(
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/refresh"
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
        final String authHeader = request.getHeader("Authorization"); // This is the line that fetches the header

        log.debug("Processing request to: {}", requestPath);

        log.info("DEBUG: Request URI: '{}'", requestPath);
        log.info("DEBUG: Public Prefixes configured: {}", PUBLIC_PREFIXES);
        log.info("DEBUG: Public Exact Match Endpoints configured: {}", PUBLIC_EXACT_MATCH_ENDPOINTS);

        // --- NEW LOGGING HERE ---
        log.info("DEBUG: Authorization Header received: '{}'", (authHeader != null ? authHeader : "NULL"));

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing or invalid Authorization header for request: {}. Header was: '{}'", requestPath, authHeader);
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7); // This extracts the token
        log.info("DEBUG: Extracted JWT (first 10 chars): '{}'", jwt.length() > 10 ? jwt.substring(0, 10) + "..." : jwt);
        log.info("DEBUG: Extracted JWT length: {}", jwt.length());
        // --- END NEW LOGGING ---

        try {
            final String userEmail = jwtUtil.extractEmail(jwt);

            if (userEmail == null) {
                log.warn("No email extracted from JWT");
                filterChain.doFilter(request, response);
                return;
            }

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

                if (jwtUtil.validateToken(jwt, userDetails.getUsername())) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.debug("Authenticated user: {}", userEmail);
                } else {
                    log.warn("Invalid JWT token for user: {}", userEmail);
                }
            }
        } catch (Exception e) {
            log.error("JWT processing error for request {}: {}", requestPath, e.getMessage(), e);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPublicEndpoint(String requestPath) {
        // ... (this method remains the same as your last version)
        log.debug("Inside isPublicEndpoint for: '{}'", requestPath);
        if (PUBLIC_EXACT_MATCH_ENDPOINTS.contains(requestPath)) {
            log.debug("'{}' is in PUBLIC_EXACT_MATCH_ENDPOINTS.", requestPath);
            return true;
        }
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
        log.debug("'{}' is NOT a public endpoint.", requestPath);
        return false;
    }
}