package com.landgo.gateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    private static final List<String> PUBLIC_PATHS = List.of(
            "/user/auth/login",
            "/user/auth/register",
            "/user/auth/verify",
            "/user/auth/forgot-password",
            "/user/auth/reset-password",
            "/user/auth/refresh-token",
            "/user/public/",
            "/user/professionals",
            "/user/professionals/",
            "/user/professionals/search",
            "/user/professionals/expertise-options",
            "/core/listings",
            "/core/professionals",
            "/core/professionals/",
            "/core/locations",
            "/core/filter-options",
            "/core/reviews",
            "/actuator",
            "/swagger-ui",
            "/v3/api-docs",
            "/payment/webhook",
            "/api/ping"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // Skip auth for public endpoints
        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        // Check for GET requests on public read endpoints
        if ("GET".equals(request.getMethod().name()) && isPublicReadPath(path)) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.info("Rejecting request without bearer token: method={} path={}", request.getMethod(), path);
            return onError(exchange, "Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);
        try {
            log.debug("JWT validation attempt for path: {}, secret length: {}", path, jwtSecret != null ? jwtSecret.length() : "null");
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.debug("JWT validation successful for path: {}, method: {}", path, request.getMethod().name());

            String userId = claims.getSubject();
            String email = claims.get("email", String.class);
            String role = claims.get("role", String.class);

            // Add user info to request headers
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-User-Id", userId)
                    .header("X-User-Email", email != null ? email : "")
                    .header("X-User-Role", role)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (Exception e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return onError(exchange, "Invalid JWT token: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        String body = String.format("{\"success\":false,\"message\":\"%s\",\"code\":\"UNAUTHORIZED\"}", message);
        org.springframework.core.io.buffer.DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::startsWith) || path.contains("/webhook");
    }

    private boolean isPublicReadPath(String path) {
        return path.startsWith("/core/listings") ||
               path.startsWith("/core/professionals") ||
               path.startsWith("/core/locations") ||
               path.startsWith("/core/filter-options") ||
               path.startsWith("/core/reviews") ||
               path.startsWith("/payment/subscriptions/plans");
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
