package io.github.photographed.authzradar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/** Default {@link DecisionLog}: INFO on logger {@code io.github.photographed.authzradar.decisions}. */
public class CommonsDecisionLog implements DecisionLog {

    private static final Log LOG = LogFactory.getLog("io.github.photographed.authzradar.decisions");

    @Override
    public void write(String line) {
        LOG.info(line);
    }
}
