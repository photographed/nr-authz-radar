package io.github.photographed.authzradar;

import java.util.Map;

/** Thin seam over the New Relic agent API so the logic can be tested without an agent. */
public interface TelemetryRecorder {

    void attribute(String key, String value);

    void attribute(String key, Number value);

    void attribute(String key, boolean value);

    void userId(String pseudonymousUserId);

    /** Records an expected error: grouped in Errors Inbox without affecting error rate or Apdex. */
    void expectedError(Throwable error, Map<String, ?> attributes);
}
