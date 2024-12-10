package org.zerock.ex3.config;


import lombok.extern.log4j.Log4j2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Log4j2
@Configuration
public class CustomSecurityConfig {
  
  
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
    log.info("filter chain...................");
    
    httpSecurity.formLogin(httpSecurityFormLoginConfigurer -> {
      httpSecurityFormLoginConfigurer.disable();
    });
    httpSecurity.logout(config -> config.disable());
    
    httpSecurity.csrf(config->{
      config.disable();});
    
    httpSecurity.sessionManagement(sessionManagementConfigurer -> {
      sessionManagementConfigurer.
          sessionCreationPolicy(SessionCreationPolicy.NEVER);
    });
    
    
    return httpSecurity.build();
  }
  
  
  @Bean
  public PasswordEncoder passwordEncoder(){
    return new BCryptPasswordEncoder();
  }
}
