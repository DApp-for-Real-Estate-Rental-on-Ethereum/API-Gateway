package ma.fstt.apigateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import ma.fstt.apigateway.filter.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Configuration
public class SecurityConfiguration {

    final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfiguration(JwtAuthenticationFilter  jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http.
                csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(ServerHttpSecurity.CorsSpec::disable) // Disable Spring Security CORS - handled by CorsWebFilter
                .authorizeExchange(
                        exchange -> exchange
                                // Public endpoints - no authentication required
                                .pathMatchers("/api/v1/auth/**").permitAll()
                                .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                // Health checks
                                .pathMatchers("/actuator/**", "/health", "/api/health").permitAll()
                                // All other endpoints require authentication
                                .anyExchange().authenticated()
                )
                .exceptionHandling(exchange ->
                        exchange
                                .authenticationEntryPoint(authenticationEntryPoint())
                )
                .addFilterAfter(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION);

        return http.build();
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",
                "http://localhost:3001",
                "http://127.0.0.1:3000",
                "http://127.0.0.1:3001"
        ));
        corsConfig.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        // Use specific headers instead of "*" to avoid conflicts
        // Include X-User-Id and X-User-Roles which are added by JwtAuthenticationFilter
        corsConfig.setAllowedHeaders(Arrays.asList(
                "Authorization", "Content-Type", "X-Requested-With", "Accept", "Origin",
                "Access-Control-Request-Method", "Access-Control-Request-Headers",
                "X-User-Id", "X-User-Roles", "x-user-id", "x-user-roles"  // Case-insensitive support
        ));
        // Expose custom headers to the frontend
        corsConfig.setExposedHeaders(Arrays.asList(
                "X-User-Id", "X-User-Roles", "Authorization"
        ));
        corsConfig.setAllowCredentials(true);
        corsConfig.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        return source;
    }
    
    /**
     * CorsWebFilter to handle CORS for all requests (including actual requests, not just preflight).
     * This is the recommended way to handle CORS in Spring WebFlux/Spring Cloud Gateway.
     * It will add CORS headers to all responses, not just OPTIONS requests.
     */
    @Bean
    public CorsWebFilter corsWebFilter() {
        return new CorsWebFilter(corsConfigurationSource());
    }
    

    @Bean
    public ServerAuthenticationEntryPoint authenticationEntryPoint() {

        return (ServerWebExchange exchange, AuthenticationException ex) -> {
            var response = exchange.getResponse();
            var request = exchange.getRequest();
            String origin = request.getHeaders().getFirst("Origin");
            
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            
            // Add CORS headers to error responses
            if (origin != null && isAllowedOrigin(origin)) {
                response.getHeaders().set("Access-Control-Allow-Origin", origin);
                response.getHeaders().set("Access-Control-Allow-Credentials", "true");
                response.getHeaders().set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH,OPTIONS");
                response.getHeaders().set("Access-Control-Allow-Headers", 
                    "Authorization,Content-Type,X-Requested-With,Accept,Origin," +
                    "Access-Control-Request-Method,Access-Control-Request-Headers," +
                    "X-User-Id,X-User-Roles,x-user-id,x-user-roles");
                response.getHeaders().set("Access-Control-Expose-Headers", 
                    "X-User-Id,X-User-Roles,Authorization");
            }

            Map<String, Object> body = new HashMap<>();

            body.put("status", HttpStatus.UNAUTHORIZED.value());
            body.put("error", "Unauthorized");
            body.put("message", ex.getMessage());
            body.put("path", request.getPath().value());


            try {
                ObjectMapper mapper = new ObjectMapper();
                byte[] bytes = mapper.writeValueAsBytes(body);
                var buffer = response.bufferFactory().wrap(bytes);
                return response.writeWith(Mono.just(buffer));
            } catch (Exception e) {
                return response.setComplete();
            }
        };
    }
    
    private boolean isAllowedOrigin(String origin) {
        return origin != null && (
            origin.equals("http://localhost:3000") ||
            origin.equals("http://localhost:3001") ||
            origin.equals("http://127.0.0.1:3000") ||
            origin.equals("http://127.0.0.1:3001")
        );
    }
}