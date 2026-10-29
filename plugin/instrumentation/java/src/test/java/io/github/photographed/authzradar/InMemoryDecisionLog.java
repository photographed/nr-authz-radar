package io.github.photographed.authzradar;

import java.util.ArrayList;
import java.util.List;

public class InMemoryDecisionLog implements DecisionLog {
    public final List<String> lines = new ArrayList<>();

    @Override
    public void write(String line) {
        lines.add(line);
    }
}
