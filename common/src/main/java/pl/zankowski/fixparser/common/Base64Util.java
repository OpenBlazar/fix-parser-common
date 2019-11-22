package pl.zankowski.fixparser.common;

import java.util.Base64;

public class Base64Util {

    public static String encode(final String data) {
        return Base64.getEncoder().encodeToString(data.getBytes(Constants.DEFAULT_CHARSET));
    }

    public static String decode(final String data) {
        return new String(Base64.getDecoder().decode(data), Constants.DEFAULT_CHARSET);
    }

}
