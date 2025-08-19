package com.snmp.PrinterMonitoring.services;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j; // Add this import for logging

@Service
@RequiredArgsConstructor
@Slf4j // Add this annotation for logging
public class MailService {

    private final JavaMailSender mailSender;

    public void sendWelcomeEmail(String toEmail, String username, String password) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject("Welcome to Printer Monitoring System!"); // Removed emoji from subject
        message.setText("Hello " + username + ",\n\n" +
                "Your account has been created successfully.\n\n" +
                "Username (Email): " + toEmail + "\n" + // Changed to show email for clarity and removed emoji
                "Temporary Password: " + password + "\n\n" + // Removed emoji
                "Please log in and change your password.\n\n" +
                "Best regards,\nAdmin Team");

        try {
            mailSender.send(message);
            log.info("Welcome email sent successfully to: {} with subject: {}", toEmail, message.getSubject());
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}. Error: {}", toEmail, e.getMessage(), e);
            throw new RuntimeException("Failed to send welcome email", e);
        }
    }
}
