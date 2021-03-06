package org.tbk.lnurl.auth;

import org.tbk.lnurl.simple.auth.SimpleK1;

import java.security.SecureRandom;

public final class SimpleK1Factory implements K1Factory {
    private static final SecureRandom RANDOM = new SecureRandom();

    private static SimpleK1 random() {
        byte[] bytes = new byte[32];

        RANDOM.nextBytes(bytes);

        return SimpleK1.fromBytes(bytes);
    }

    @Override
    public K1 create() {
        return random();
    }
}
