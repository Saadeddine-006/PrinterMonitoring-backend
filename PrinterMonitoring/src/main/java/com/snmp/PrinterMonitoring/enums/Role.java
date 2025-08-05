package com.snmp.PrinterMonitoring.enums;

import org.springframework.security.core.GrantedAuthority;

public enum Role implements GrantedAuthority {
    ADMIN,
    TECHNICIAN,
    VIEWER;

    @Override
    public String getAuthority() {
        // This is the crucial change: Prefix with "ROLE_"
        return "ROLE_" + name(); // Now returns "ROLE_ADMIN", "ROLE_TECHNICIAN", etc.
    }
}