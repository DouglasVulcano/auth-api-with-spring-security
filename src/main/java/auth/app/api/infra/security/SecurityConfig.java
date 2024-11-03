package auth.app.api.infra.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    SecurityFilter securityFilter;

    /**
     * Configura o filtro de segurança principal da aplicação.
     * Define as regras de acesso, gerenciamento de sessão e filtros de
     * autenticação.
     *
     * @param http - Objeto HttpSecurity para configuração das permissões e
     *             segurança
     * @return SecurityFilterChain - Cadeia de filtros de segurança configurada
     * @throws Exception - Exceção genérica em caso de falha na configuração de
     *                   segurança
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Desabilita a proteção CSRF, pois a aplicação é Stateless (sem estado)
                .csrf(csrf -> csrf.disable())
                // Define a política de criação de sessão como STATELESS, ou seja, sem manter
                // estado entre requisições
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Configura as regras de autorização para as requisições HTTP
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/register").permitAll()
                        // Exige autenticação para qualquer outra requisição
                        .anyRequest().authenticated())
                // Adiciona o filtro personalizado antes do filtro padrão de autenticação de
                // usuário e senha
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class);

        // Retorna a cadeia de filtros configurada
        return http.build();
    }

    /**
     * Define o encoder de senha, utilizando o BCrypt para criptografar as senhas
     * dos usuários.
     *
     * @return PasswordEncoder - Instância do encoder BCrypt para senhas
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Configura o AuthenticationManager para gerenciar o processo de autenticação.
     *
     * @param authenticationConfiguration - Configuração de autenticação do Spring
     *                                    Security
     * @return AuthenticationManager - Instância do gerenciador de autenticação
     * @throws Exception - Exceção em caso de erro na configuração
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
