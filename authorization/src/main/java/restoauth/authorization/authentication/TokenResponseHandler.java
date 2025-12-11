package restoauth.authorization.authentication;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class TokenResponseHandler implements AuthenticationSuccessHandler {

    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

    private static final long NEW_TOKEN_THRESHOLD_SECONDS = 1;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        // 1. 인증 결과 객체 형변환 (여기에 모든 정보가 다 있습니다)
        OAuth2AccessTokenAuthenticationToken accessTokenAuth =
                (OAuth2AccessTokenAuthenticationToken) authentication;

        OAuth2AccessToken accessToken = accessTokenAuth.getAccessToken();
        OAuth2RefreshToken refreshToken = accessTokenAuth.getRefreshToken();

        // 기존에 있을 수 있는 파라미터를 가져옵니다.
        Map<String, Object> additionalParameters = new HashMap<>(accessTokenAuth.getAdditionalParameters());

        // ==========================================
        // 🔥 [핵심] 상황에 따른 조건부 로직 (Custom Logic)
        // ==========================================

        // 상황 1: 특정 클라이언트 ID인지 확인
        Instant issuedAt = accessToken.getIssuedAt();
        Instant now = Instant.now();

        boolean isExistingToken = false;

        if (issuedAt != null) {
            // 현재 시간과 발급 시간의 차이 계산
            long diffSeconds = ChronoUnit.SECONDS.between(issuedAt, now);

            // 차이가 임계값(1초)보다 크다면 "예전에 발급된 토큰"으로 판단
            if (diffSeconds > NEW_TOKEN_THRESHOLD_SECONDS) {
                isExistingToken = true;
            }
        }

        // JSON 필드 추가
        additionalParameters.put("is_existing_token", isExistingToken);

        // 2. 응답 객체 다시 빌드 (위에서 만든 맵을 주입)
        OAuth2AccessTokenResponse.Builder builder =
                OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                        .tokenType(accessToken.getTokenType())
                        .scopes(accessToken.getScopes());

        if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }

        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }

        // 여기서 커스텀 파라미터를 최종적으로 넣습니다.
        builder.additionalParameters(additionalParameters);

        OAuth2AccessTokenResponse tokenResponse = builder.build();

        // 3. JSON 변환 및 응답 출력
        this.accessTokenHttpResponseConverter.write(tokenResponse, null, new ServletServerHttpResponse(response));
    }
}
