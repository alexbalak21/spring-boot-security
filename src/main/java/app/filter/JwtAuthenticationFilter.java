package app.filter;

import app.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        log.debug("[JwtFilter] Instantiating JwtAuthenticationFilter.");
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain
    ) throws ServletException, IOException {

        log.debug("🔥 [JwtFilter] Filter triggered for URI: {}", request.getRequestURI());

        try {
            final String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.debug("[JwtFilter] No Bearer token found. Continuing unauthenticated.");
                filterChain.doFilter(request, response);
                return;
            }

            final String jwt = authHeader.substring(7);
            final String username = jwtService.usernameFromToken(jwt).orElse(null);
            log.debug("[JwtFilter] Token extracted. Username: {}", username);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                log.debug("[JwtFilter] User loaded: {}", userDetails.getUsername());

                if (jwtService.validateToken(jwt, userDetails)) {
                    log.debug("[JwtFilter] Token valid. Setting authentication context.");

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("[JwtFilter] SecurityContext populated for user: {}", username);
                } else {
                    log.warn("[JwtFilter] Token validation failed for user: {}", username);
                }
            } else {
                log.debug("[JwtFilter] Skipping authentication. Context already populated or username missing.");
            }
        } catch (Exception e) {
            log.error("[JwtFilter] Exception during JWT processing: {}", e.getMessage(), e);
        }

        log.debug("[JwtFilter] Continuing with filter chain.");
        filterChain.doFilter(request, response);
    }
}
