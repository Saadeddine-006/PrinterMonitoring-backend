    package com.snmp.PrinterMonitoring.dtos.users;

    import com.snmp.PrinterMonitoring.enums.Role;
    import lombok.*;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public class UserResponseDTO {

        private Long id;
        private String fullName;
        private String email;
        private Role role;
        private boolean active;
    }