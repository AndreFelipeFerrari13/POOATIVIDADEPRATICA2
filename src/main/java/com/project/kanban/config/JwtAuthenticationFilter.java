package com.project.kanban.config;

import com.project.kanban.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService tokenService;
    private final UserDetailsService usuarioService;

    public JwtAuthenticationFilter(JwtService tokenService, UserDetailsService usuarioService) {
        this.tokenService = tokenService;
        this.usuarioService = usuarioService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String headerAutorizacao = req.getHeader("Authorization");

        if (headerAutorizacao == null || !headerAutorizacao.startsWith("Bearer ")) {
            chain.doFilter(req, res);
            return;
        }

        String token = headerAutorizacao.substring(7);
        String usuario;

        try {
            usuario = tokenService.extractUsername(token);
        } catch (Exception e) {
            System.out.println("Falha na extração do JWT: " + e.getMessage());
            chain.doFilter(req, res);
            return;
        }

        if (usuario != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = usuarioService.loadUserByUsername(usuario);
            if (tokenService.validateToken(token, userDetails.getUsername())) {
                UsernamePasswordAuthenticationToken autenticacao = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                SecurityContextHolder.getContext().setAuthentication(autenticacao); // Define a autenticação no contexto
            } else {
                System.out.println("Falha na validação do JWT");
            }
        }
        chain.doFilter(req, res);
    }
}
