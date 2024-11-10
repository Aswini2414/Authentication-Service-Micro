package com.security.config;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.datasource.UserCredentialsDataSourceAdapter;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.security.entity.UserCredential;
import com.security.repository.UserCredentialRepository;

public class CustomUserDetailsService implements UserDetailsService{
	
	@Autowired
	private UserCredentialRepository repository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<UserCredential> credential = repository.findByName(username);
		return credential.map(CustomUserDetails::new).orElseThrow(()->new UsernameNotFoundException("username not found"+username));
	}
	
	
	

}
