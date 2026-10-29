package io.github.photographed.authzradar;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

/**
 * Decides {@code client.type} ({@code web} / {@code mobile} / {@code api_key} / {@code service} /
 * {@code unknown}). Provide your own bean; the default sends nothing. Do not trust headers the
 * client can set freely; prefer how the request authenticated.
 */
@FunctionalInterface
public interface ClientTypeResolver {

    /** @return the client type, or {@code null} to send nothing */
    String resolve(HttpServletRequest request, Authentication authentication);
}
