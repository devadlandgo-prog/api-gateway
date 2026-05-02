package com.landgo.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Collections;

@Configuration
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOriginPattern("*");         // Allow all origins
        config.addAllowedMethod("*");                // Allow GET, POST, PUT, PATCH, DELETE, OPTIONS
        config.addAllowedHeader("*");                // Allow all headers
        config.setExposedHeaders(Collections.singletonList("*")); // Expose all response headers
        config.setAllowCredentials(false);           // Must be false when origin is *
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return new CorsWebFilter(source);
    }
}
