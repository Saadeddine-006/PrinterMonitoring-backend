package com.snmp.PrinterMonitoring.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
@Tag(name = "System", description = "System status and welcome endpoints")
public class WelcomeController {

    @GetMapping(produces = MediaType.TEXT_PLAIN_VALUE)
    @Operation(
            summary = "Welcome message",
            description = "Public welcome endpoint for the application",
            responses = {
                    @ApiResponse(responseCode = "200", description = "System is operational")
            }
    )
    public ResponseEntity<String> home() {
        return ResponseEntity.ok()
                .header("X-System-Version", "1.0")
                .body("Welcome to Printer Monitoring System - Please login at /api/auth/login to continue");
    }

    @GetMapping(value = "/welcome", produces = MediaType.TEXT_PLAIN_VALUE)
    @Operation(
            summary = "Authenticated welcome",
            description = "Welcome message for authenticated users",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<String> welcome() {
        return ResponseEntity.ok()
                .header("X-System-Version", "1.0")
                .body("Printer Monitoring System is running successfully! Use /api endpoints for operations");
    }

    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "System health",
            description = "Check system health status",
            responses = {
                    @ApiResponse(responseCode = "200", description = "System is healthy"),
                    @ApiResponse(responseCode = "503", description = "System is unavailable")
            }
    )
    public ResponseEntity<HealthStatus> health() {
        HealthStatus health = new HealthStatus(
                "healthy",
                System.currentTimeMillis(),
                "All systems operational"
        );
        return ResponseEntity.ok(health);
    }

    @GetMapping(value = "/status", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(
            summary = "System status",
            description = "Detailed system status information",
            security = @SecurityRequirement(name = "bearerAuth")
    )
    public ResponseEntity<SystemStatus> status() {
        SystemStatus status = new SystemStatus(
                Runtime.version().toString(),
                Runtime.getRuntime().availableProcessors(),
                Runtime.getRuntime().maxMemory()
        );
        return ResponseEntity.ok(status);
    }

    // Records for response objects
    private record HealthStatus(String status, long timestamp, String message) {}
    private record SystemStatus(String javaVersion, int availableProcessors, long maxMemory) {}
}