package com.example;

import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.text.StringSubstitutor;

public class App {
    private final StringSubstitutor interpolator = StringSubstitutor.createInterpolator();

    // Reachable: StringSubstitutor.replace (CVE-2022-42889), on a typed field.
    String expand(String input) {
        return interpolator.replace(input);
    }

    // commons-collections is used, but InvokerTransformer.transform
    // (CVE-2015-7501) is never called.
    boolean empty(List<String> items) {
        return CollectionUtils.isEmpty(items);
    }

    public static void main(String[] args) {
        App app = new App();
        if (!app.empty(List.of(args))) {
            System.out.println(app.expand(args[0]));
        }
    }
}
