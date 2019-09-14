package pl.zankowski.fixparser.common.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider {

    private static final String AUTHORITIES_KEY = "auth";
    private static final Logger LOG = LoggerFactory.getLogger(TokenProvider.class);

    private final JwtConfigurationProperties jwtConfig;

    private String secretKey;
    private long tokenValidity;
    private long tokenValidityForRememberMe;

    @Autowired
    public TokenProvider(final JwtConfigurationProperties jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    @PostConstruct
    public void init() {
        secretKey = jwtConfig.getSecret();
        tokenValidity = jwtConfig.getExpiration();
        tokenValidityForRememberMe = jwtConfig.getExpiration();
    }

    public String createAuthToken(final Authentication authentication, final boolean rememberMe) {
        final String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        final long validity = Instant.now().plusMillis(getTokenValidity(rememberMe)).toEpochMilli();

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(SignatureAlgorithm.HS512, secretKey)
                .setExpiration(new Date(validity))
                .compact();
    }

    private long getTokenValidity(final boolean rememberMe) {
        return rememberMe ? tokenValidityForRememberMe : tokenValidity;
    }

    public Authentication getAuthentication(final String authToken) {
        final Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(authToken)
                .getBody();

        final Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        final User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, authToken, authorities);
    }

    public boolean validateToken(final String authToken) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(authToken);
            return true;
        } catch (final SignatureException e) {
            LOG.info("Invalid JWT signature.");
            LOG.trace("Invalid JWT signature trace: {}", e);
        } catch (final MalformedJwtException e) {
            LOG.info("Invalid JWT token.");
            LOG.trace("Invalid JWT token trace: {}", e);
        } catch (final ExpiredJwtException e) {
            LOG.info("Expired JWT token.");
            LOG.trace("Expired JWT token trace: {}", e);
        } catch (final UnsupportedJwtException e) {
            LOG.info("Unsupported JWT token.");
            LOG.trace("Unsupported JWT token trace: {}", e);
        } catch (final IllegalArgumentException e) {
            LOG.info("JWT token compact of handler are invalid.");
            LOG.trace("JWT token compact of handler are invalid trace: {}", e);
        }
        return false;
    }

}
