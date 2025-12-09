package ma.fstt.apigateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Removes CORS headers from downstream services and ensures gateway CORS headers are present.
 * The gateway's SecurityConfiguration handles CORS, so downstream services
 * should not add their own CORS headers.
 * 
 * This filter runs AFTER the gateway routes to downstream services but BEFORE
 * the response is sent to the client, allowing us to strip downstream CORS headers
 * and ensure gateway CORS headers are present on all responses.
 */
@Component
@Slf4j
public class RemoveDownstreamCorsFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpResponse originalResponse = exchange.getResponse();
        String origin = exchange.getRequest().getHeaders().getFirst("Origin");
        String method = exchange.getRequest().getMethod() != null ? exchange.getRequest().getMethod().name() : "GET";
        
        log.debug("RemoveDownstreamCorsFilter: Processing {} request from origin: {}", method, origin);
        
        // Handle OPTIONS preflight requests immediately - MUST return before chain.filter
        if ("OPTIONS".equals(method)) {
            if (origin != null && isAllowedOrigin(origin)) {
                log.debug("Handling OPTIONS preflight request for origin: {}", origin);
                originalResponse.setStatusCode(org.springframework.http.HttpStatus.OK);
                originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
                originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, 
                        "GET,POST,PUT,DELETE,PATCH,OPTIONS");
                originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, 
                        "Authorization,Content-Type,X-Requested-With,Accept,Origin," +
                        "Access-Control-Request-Method,Access-Control-Request-Headers," +
                        "X-User-Id,X-User-Roles,x-user-id,x-user-roles");
                originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_MAX_AGE, "3600");
                return originalResponse.setComplete();
            }
        }
        
        // For non-OPTIONS requests, add CORS headers immediately to ensure they're present
        // even if the request fails or response is committed early
        if (origin != null && isAllowedOrigin(origin)) {
            originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
            originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, 
                    "GET,POST,PUT,DELETE,PATCH,OPTIONS");
            originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, 
                    "Authorization,Content-Type,X-Requested-With,Accept,Origin," +
                    "Access-Control-Request-Method,Access-Control-Request-Headers," +
                    "X-User-Id,X-User-Roles,x-user-id,x-user-roles");
            originalResponse.getHeaders().set(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, 
                    "X-User-Id,X-User-Roles,Authorization");
        }
        
        // Use ServerHttpResponseDecorator to intercept and ensure CORS headers are always present
        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
            @Override
            @SuppressWarnings("null")
            public HttpHeaders getHeaders() {
                HttpHeaders headers = super.getHeaders();
                
                // Remove any CORS headers that downstream services might have added
                headers.remove(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN);
                headers.remove(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS);
                headers.remove(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS);
                headers.remove(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS);
                headers.remove(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS);
                headers.remove(HttpHeaders.ACCESS_CONTROL_MAX_AGE);
                
                // Always add gateway CORS headers if origin is present and allowed
                // This ensures CORS headers are present even if CorsWebFilter didn't run
                if (origin != null && isAllowedOrigin(origin)) {
                    headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                    headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
                    headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, 
                            "GET,POST,PUT,DELETE,PATCH,OPTIONS");
                    headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, 
                            "Authorization,Content-Type,X-Requested-With,Accept,Origin," +
                            "Access-Control-Request-Method,Access-Control-Request-Headers," +
                            "X-User-Id,X-User-Roles,x-user-id,x-user-roles");
                    headers.set(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, 
                            "X-User-Id,X-User-Roles,Authorization");
                }
                
                return headers;
            }
            
            @Override
            public Mono<Void> writeWith(org.reactivestreams.Publisher<? extends org.springframework.core.io.buffer.DataBuffer> body) {
                // Ensure CORS headers are set before writing the response body
                HttpHeaders headers = getHeaders();
                if (origin != null && isAllowedOrigin(origin)) {
                    // Force set headers again to ensure they're present
                    headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                    headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
                    headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, 
                            "GET,POST,PUT,DELETE,PATCH,OPTIONS");
                    headers.set(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, 
                            "Authorization,Content-Type,X-Requested-With,Accept,Origin," +
                            "Access-Control-Request-Method,Access-Control-Request-Headers," +
                            "X-User-Id,X-User-Roles,x-user-id,x-user-roles");
                    headers.set(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, 
                            "X-User-Id,X-User-Roles,Authorization");
                }
                return super.writeWith(body);
            }
        };
        
        return chain.filter(exchange.mutate().response(decoratedResponse).build());
    }
    
    private boolean isAllowedOrigin(String origin) {
        return origin != null && (
            origin.equals("http://localhost:3000") ||
            origin.equals("http://localhost:3001") ||
            origin.equals("http://127.0.0.1:3000")
        );
    }

    @Override
    public int getOrder() {
        // Run BEFORE NettyWriteResponseFilter (order -1) to ensure CORS headers are set
        // This ensures headers are added before the response is committed
        // Using -2 to run just before NettyWriteResponseFilter
        return -2;
    }
}

