package restoauth.authorization;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "users")
public class User {

    @Id
    private String username;
    private String password;
    private String role;

    public static User create(String username, String password, String role, PasswordEncoder passwordEncoder) {
        return new User(username, passwordEncoder.encode(password), role);
    }

    private User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }
}