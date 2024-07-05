package com.jh.apigatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
@Slf4j
public class CustomFilter extends AbstractGatewayFilterFactory<CustomFilter.Config> {

    @Value("${jwt.secret.key}")
    private String jwtSecret;

    public CustomFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            String authHeader = request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION).get(0);
            if (!authHeader.startsWith("Bearer ")) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            String token = authHeader.substring(7);

            try {
                Claims claims = Jwts.parser()
                        .setSigningKey(jwtSecret)
                        .parseClaimsJws(token)
                        .getBody();

                log.info("JWT Claims: ");
                for (Map.Entry<String, Object> entry : claims.entrySet()) {
                    log.info("{}: {}", entry.getKey(), entry.getValue());
                    request = exchange.getRequest().mutate()
                            .header("X-Claim-" + entry.getKey(), entry.getValue().toString())
                            .build();
                }

            } catch (Exception e) {
                log.error("JWT validation failed", e);
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                return response.setComplete();
            }

            log.info("Custom PRE filter: request uri -> {}", request.getURI());
            log.info("Custom PRE filter: request id -> {}", request.getId());

            return chain.filter(exchange.mutate().request(request).build()).then(Mono.fromRunnable(() -> {
                log.info("Custom POST filter: response status code -> {}", response.getStatusCode());
            }));
        };
    }

    @Data
    public static class Config {
        private boolean preLogger;
        private boolean postLogger;
    }
}
