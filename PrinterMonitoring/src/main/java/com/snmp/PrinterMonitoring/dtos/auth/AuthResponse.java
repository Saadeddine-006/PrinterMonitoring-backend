package com.snmp.PrinterMonitoring.dtos.auth;

import com.snmp.PrinterMonitoring.dtos.users.UserResponseDTO; // IMPORTANT: Make sure this is imported
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Builder;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthResponse {
    private String token;
    private String refreshToken;  // This is correct as a separate field
    private String message;       // Optional status message

    private UserResponseDTO user; // <--- ADD THIS LINE! This is the missing user object
}
