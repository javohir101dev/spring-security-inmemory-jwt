package securityApp.jwt;

import com.google.common.net.HttpHeaders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@ConfigurationProperties(prefix = "application.jwt")
@Configuration
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class JwtConfiguration {

    private String secretKey;
    private String tokenPrefix;
    private long tokenExperationAfterDays;



    public String getAuthorization(){
        return HttpHeaders.AUTHORIZATION;
    }

}
