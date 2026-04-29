package common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class ReportUtils {
    private ReportUtils() {
    }

    public static void printReport(String name, long startNanos, Object result) {
        double elapsedSeconds = (System.nanoTime() - startNanos) / 1_000_000_000.0;
        System.out.println();
        System.out.println("=== " + name + " ===");
        System.out.printf(Locale.ROOT, "time_seconds: %.6f%n", elapsedSeconds);
        System.out.println("output: " + preview(result, 4));
    }

    public static Object preview(Object value, int maxItems) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> shown = new LinkedHashMap<String, Object>();
            int count = 0;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (count >= maxItems) {
                    shown.put("...", (map.size() - maxItems) + " more");
                    break;
                }
                shown.put(String.valueOf(entry.getKey()), preview(entry.getValue(), maxItems));
                count++;
            }
            return shown;
        }
        if (value instanceof List<?> list) {
            List<Object> shown = new ArrayList<Object>();
            for (int i = 0; i < list.size() && i < maxItems; i++) {
                shown.add(preview(list.get(i), maxItems));
            }
            if (list.size() > maxItems) {
                shown.add("... " + (list.size() - maxItems) + " more");
            }
            return shown;
        }
        return value;
    }
}
