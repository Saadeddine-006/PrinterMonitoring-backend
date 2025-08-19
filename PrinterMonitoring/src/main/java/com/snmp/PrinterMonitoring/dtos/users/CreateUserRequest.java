package com.snmp.PrinterMonitoring.dtos.users;

import com.snmp.PrinterMonitoring.enums.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateUserRequest {
    @NotBlank
    @Size(min = 2, max = 50)
    private String fullName;

    @NotBlank
    @Email
    private String email;

    private Role role;
}