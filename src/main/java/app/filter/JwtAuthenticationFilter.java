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
import java.util.Enumeration;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        log.debug("✅ [JwtFilter] JwtAuthenticationFilter constructor fired.");
    }

    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain
    ) throws ServletException, IOException {

        log.debug("🔥 [JwtFilter] doFilterInternal() invoked for URI: {}", request.getRequestURI());

        // Show all headers
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String header = headerNames.nextElement();
            log.debug("🔍 [JwtFilter] Header: {} = {}", header, request.getHeader(header));
        }

        try {
            final String authHeader = request.getHeader("Authorization");

            if (authHeader == null) {
                log.debug("⚠️ [JwtFilter] Missing Authorization header. Skipping JWT filter.");
                filterChain.doFilter(request, response);
                return;
            }

            if (!authHeader.startsWith("Bearer ")) {
                log.debug("⚠️ [JwtFilter] Authorization header found, but does not start with 'Bearer '. Value: {}", authHeader);
                filterChain.doFilter(request, response);
                return;
            }

            final String jwt = authHeader.substring(7);
            log.debug("🧪 [JwtFilter] Extracted JWT token: {}", jwt);

            final String username = jwtService.usernameFromToken(jwt).orElse(null);
            log.debug("🔎 [JwtFilter] Username extracted: {}", username);

            if (username == null) {
                log.debug("⚠️ [JwtFilter] Username not found in token. Skipping authentication.");
                filterChain.doFilter(request, response);
                return;
            }

            if (SecurityContextHolder.getContext().getAuthentication() != null) {
                log.debug("ℹ️ [JwtFilter] SecurityContext already contains authentication. Skipping.");
                filterChain.doFilter(request, response);
                return;
            }

            log.debug("🔑 [JwtFilter] Loading user details for: {}", username);
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            log.debug("🔐 [JwtFilter] Validating token for user: {}", username);
            if (jwtService.validateToken(jwt, userDetails)) {
                log.debug("✅ [JwtFilter] Token is valid. Creating authentication token.");

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);

                log.debug("🔒 [JwtFilter] SecurityContext successfully updated for user: {}", username);
            } else {
                log.warn("❌ [JwtFilter] Token validation failed for user: {}", username);
            }

        } catch (Exception e) {
            log.error("💥 [JwtFilter] Exception during JWT authentication: {}", e.getMessage(), e);
        }

        log.debug("➡️ [JwtFilter] Passing request down the filter chain.");
        filterChain.doFilter(request, response);
    }
}
