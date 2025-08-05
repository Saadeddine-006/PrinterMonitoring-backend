package com.snmp.PrinterMonitoring.dtos.users;

import com.snmp.PrinterMonitoring.enums.Role;
import jakarta.validation.constraints.Size;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UpdateUserRequest {
    @Size(min = 2, max = 50)
    private String fullName;

    private Role role;
}