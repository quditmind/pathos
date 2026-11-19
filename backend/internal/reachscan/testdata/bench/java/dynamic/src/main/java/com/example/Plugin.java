package com.example;

import java.lang.reflect.Method;

public class Plugin {
    // Reflection: the class and method are named at run time, so
    // StringSubstitutor.replace may be called without a call in the code.
    public static Object call(String className, String methodName, String arg) throws Exception {
        Class<?> cls = Class.forName(className);
        Method m = cls.getMethod(methodName, String.class);
        return m.invoke(cls.getDeclaredConstructor().newInstance(), arg);
    }

    public static void main(String[] args) throws Exception {
        System.out.println(call(args[0], args[1], args[2]));
    }
}
