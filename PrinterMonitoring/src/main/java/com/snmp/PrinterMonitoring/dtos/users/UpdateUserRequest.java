package com.snmp.PrinterMonitoring.dtos.users;

import com.snmp.PrinterMonitoring.enums.Role;
import jakarta.validation.constraints.Email; // Import for @Email validation
import jakarta.validation.constraints.NotBlank; // Import for @NotBlank validation
import jakarta.validation.constraints.Size;
import lombok.*; // Keep all Lombok annotations

@Data // Provides getters, setters, equals, hashCode, and toString
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UpdateUserRequest {

    @Size(min = 2, max = 50, message = "Full name must be between 2 and 50 characters")
    @NotBlank(message = "Full name cannot be blank") // Ensure it's not just null, but also not empty
    private String fullName;

    @NotBlank(message = "Email cannot be blank") // Email should not be empty
    @Email(message = "Invalid email format") // Validate email structure
    private String email; // <--- ADD THIS LINE! This is the missing email field

    private Role role; // Role is already here
}
