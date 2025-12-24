package ma.fstt.apigateway.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import lombok.extern.slf4j.Slf4j;
import ma.fstt.apigateway.service.JWTService;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@Slf4j
public class JwtAuthenticationFilter implements WebFilter {

    private final JWTService jwtService;

    JwtAuthenticationFilter(JWTService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // If no Authorization header or doesn't start with "Bearer ", skip JWT
        // validation
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        String token = authorizationHeader.substring(7).trim();

        // Validate token format before processing (JWT should have 2 dots)
        if (token.isEmpty() || token.split("\\.").length != 3) {
            log.warn("Invalid JWT token format in request to: {}", exchange.getRequest().getPath());
            return chain.filter(exchange);
        }

        return validateAndExtractAuthentication(token)
                .flatMap(auth -> {
                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(exchange.getRequest().mutate()
                                    .header("X-User-Id", jwtService.extractUsername(token))
                                    .header("X-User-Roles", jwtService.extractRoles(token).toString())
                                    .build())
                            .build();
                    return chain.filter(mutatedExchange)
                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
                })
                .onErrorResume(e -> {
                    log.warn("JWT validation failed for request to {}: {}",
                            exchange.getRequest().getPath(), e.getMessage());
                    // Continue the filter chain without authentication
                    // Spring Security will handle authorization
                    return chain.filter(exchange);
                });
    }

    public Mono<Authentication> validateAndExtractAuthentication(String token) {
        try {
            String username = jwtService.extractUsername(token);
            Set<String> roles = jwtService.extractRoles(token);

            List<SimpleGrantedAuthority> authorities = roles == null
                    ? List.of(new SimpleGrantedAuthority(""))
                    : roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

            User principal = new User(username, "", authorities);

            Authentication authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);

            return Mono.just(authentication);

        } catch (ExpiredJwtException | MalformedJwtException | IllegalArgumentException
                | io.jsonwebtoken.security.SignatureException e) {
            log.error("JWT parsing error: {}", e.getMessage());
            return Mono.error(e);
        }
    }
}
