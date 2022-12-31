package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsConfig;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다.
                .and()
                .addFilter(corsConfig)
                .formLogin().disable() // Form으로 로그인 하지 않겠다.
                .httpBasic().disable() // http 통신을 하지 않겠다.
                .authorizeHttpRequests(auth -> {
                    try {
                        auth
                            .antMatchers("/api/v1/user/**")
                                .hasAnyRole("USER", "MANAGER", "ADMIN")
                            .antMatchers("/api/v1/manager/**")
                                .hasAnyRole("MANAGER", "ADMIN")
                            .antMatchers("/api/v1/admin/**")
                                .hasAnyRole("ADMIN")
                                .anyRequest().permitAll();

                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                })
                .build();
    }
}
