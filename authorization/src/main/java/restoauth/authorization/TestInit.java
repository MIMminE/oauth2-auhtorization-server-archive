package restoauth.authorization;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

//@Component
@RequiredArgsConstructor
public class TestInit implements CommandLineRunner {

    private final UserRepository userRepository;
//    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
//        User testUser = User.create("testUser", "password", "user", passwordEncoder);
//        userRepository.save(testUser);
    }
}
