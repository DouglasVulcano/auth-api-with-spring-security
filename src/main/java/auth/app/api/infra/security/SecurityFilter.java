package auth.app.api.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import auth.app.api.domain.User;
import auth.app.api.repositories.UserRepository;

import java.io.IOException;
import java.util.Collections;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    TokenService tokenService;

    @Autowired
    UserRepository userRepository;

    /**
     * Este método é chamado em cada requisição. Ele recupera o token de
     * autenticação
     * do cabeçalho da requisição, valida o token e, se válido, autentica o usuário
     * associando-o ao contexto de segurança.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Recupera o token de autenticação do cabeçalho da requisição
        var token = this.recoverToken(request);

        // Valida o token e obtém o login (email) associado ao usuário
        var login = tokenService.validateToken(token);

        // Se o login não for nulo, o token é válido e o usuário existe
        if (login != null) {
            // Procura o usuário no banco de dados pelo email retornado pelo token
            User user = userRepository.findByEmail(login)
                    .orElseThrow(() -> new RuntimeException("User Not Found"));

            // Define a autoridade padrão do usuário como "ROLE_USER"
            var authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));

            // Cria um objeto de autenticação com o usuário autenticado e suas permissões
            var authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);

            // Associa a autenticação ao contexto de segurança da aplicação
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        // Passa a requisição para o próximo filtro da cadeia
        filterChain.doFilter(request, response);
    }

    /**
     * Este método recupera o token de autenticação do cabeçalho "Authorization"
     * da requisição HTTP. Se o cabeçalho estiver ausente ou vazio, retorna null.
     */
    private String recoverToken(HttpServletRequest request) {
        // Obtém o valor do cabeçalho "Authorization"
        var authHeader = request.getHeader("Authorization");

        // Retorna null se o cabeçalho não estiver presente
        if (authHeader == null)
            return null;

        // Remove o prefixo "Bearer " do token e retorna o token limpo
        return authHeader.replace("Bearer ", "");
    }
}
