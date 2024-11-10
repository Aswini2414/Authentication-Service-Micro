package com.security.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.AuthorizeRequestsDsl;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.security.dto.AuthRequest;
import com.security.entity.UserCredential;
import com.security.service.AuthService;

@RestController
@RequestMapping("/auth")
@CrossOrigin
public class AuthController {

	@Autowired
	private AuthService service;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	
	@PostMapping("/register")
    public ResponseEntity<?> addNewUserAndGenerateToken(@RequestBody UserCredential user) throws Exception {
		
		if (service.isUserExistByEmail(user.getEmail())) {
            // If user already exists, return a conflict response
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists with email: " + user.getEmail());
        }
		
		try {
			// Step 1: Register the new user
	        service.saveUser(user);
	        return ResponseEntity.status(HttpStatus.CREATED).body("Signup successful");
		}catch(Exception e) {
			throw new Exception(e.getMessage());
		}
       
    }
	
	@PostMapping("/validate")
	public ResponseEntity<?> validateToken(@RequestBody UserCredential user) {
	    // Step 1: Check if the user exists in the database
	    if (!service.isUserExistByEmail(user.getEmail())) {
	        // If the user doesn't exist, return a 404 status with a message to sign up
	        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found. Please sign up first.");
	    }
	    
	    String token = service.generateToken(user.getName());

        // Step 4: Return success message and token in response
        Map<String, String> response = new HashMap<>();
        response.put("message", "Login successful");
        response.put("token", token);
        return ResponseEntity.ok(response);
	  
	}

	
	@GetMapping("/validate")
    public String validateToken(@RequestParam("token") String token) {
        service.validateToken(token);
        return "Token is valid";
    }
}
