package io.github.photographed.authzradar;

import com.newrelic.api.agent.NewRelic;
import java.util.Map;

/** Sends attributes to the current New Relic transaction. No-op when the agent is not attached. */
public class NewRelicRecorder implements TelemetryRecorder {

    @Override
    public void attribute(String key, String value) {
        NewRelic.addCustomParameter(key, value);
    }

    @Override
    public void attribute(String key, Number value) {
        NewRelic.addCustomParameter(key, value);
    }

    @Override
    public void attribute(String key, boolean value) {
        NewRelic.addCustomParameter(key, value);
    }

    @Override
    public void userId(String pseudonymousUserId) {
        NewRelic.setUserId(pseudonymousUserId);
    }

    @Override
    public void transactionName(String category, String name) {
        NewRelic.setTransactionName(category, name);
    }

    @Override
    public void expectedError(Throwable error, Map<String, ?> attributes) {
        NewRelic.noticeError(error, attributes, true);
    }
}
