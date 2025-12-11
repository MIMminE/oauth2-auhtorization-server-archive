package restoauth.authorization.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController("/test")
@RequiredArgsConstructor
public class TestController {


    @GetMapping("/{tokenId}")
    public String test(@PathVariable String tokenId) {
        return "test";
    }
}
