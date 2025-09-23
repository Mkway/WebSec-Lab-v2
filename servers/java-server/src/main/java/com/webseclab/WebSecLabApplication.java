package com.webseclab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.CrossOrigin;

@SpringBootApplication
@CrossOrigin(origins = "*")
public class WebSecLabApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebSecLabApplication.class, args);
    }
}