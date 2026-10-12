package com.cpr.payments;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

// The default in-memory user (with a generated password printed to the log) is excluded:
// authentication will be implemented by the team, never by a framework default.
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
public class PaymentsApplication {

    public static void main(String[] args) {
        SpringApplication.run(PaymentsApplication.class, args);
    }
}
