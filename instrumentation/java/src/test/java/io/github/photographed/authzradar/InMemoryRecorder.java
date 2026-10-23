package io.github.photographed.authzradar;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Captures what would be sent to New Relic. */
public class InMemoryRecorder implements TelemetryRecorder {

    public final Map<String, Object> attributes = new LinkedHashMap<>();
    public final List<Throwable> expectedErrors = new ArrayList<>();
    public String userId;

    public void reset() {
        attributes.clear();
        expectedErrors.clear();
        userId = null;
    }

    @Override public void attribute(String key, String value) { attributes.put(key, value); }
    @Override public void attribute(String key, Number value) { attributes.put(key, value); }
    @Override public void attribute(String key, boolean value) { attributes.put(key, value); }
    @Override public void userId(String id) { userId = id; }
    @Override public void expectedError(Throwable error, Map<String, ?> attrs) { expectedErrors.add(error); }
}
