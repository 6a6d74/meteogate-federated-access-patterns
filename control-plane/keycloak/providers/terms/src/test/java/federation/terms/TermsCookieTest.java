package federation.terms;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class TermsCookieTest {
    private static final String SECRET = "s".repeat(40);
    private static final long NOW = 1_800_000_000L;

    private final String cookie = TermsCookie.issue(SECRET, "user-1", "2026-11-02", NOW + 3600);

    @Test
    void validForTheSameUserVersionAndTime() {
        assertTrue(TermsCookie.valid(SECRET, cookie, "user-1", "2026-11-02", NOW));
    }

    @Test
    void anotherUserOnTheSameBrowserIsAsked() {
        assertFalse(TermsCookie.valid(SECRET, cookie, "user-2", "2026-11-02", NOW));
    }

    @Test
    void newTermsAskAgain() {
        assertFalse(TermsCookie.valid(SECRET, cookie, "user-1", "2026-12-01", NOW));
    }

    @Test
    void expired() {
        assertFalse(TermsCookie.valid(SECRET, cookie, "user-1", "2026-11-02", NOW + 3600));
    }

    @Test
    void forgedOrExtended() {
        String[] p = cookie.split("\\.");
        assertFalse(TermsCookie.valid(SECRET, p[0] + "." + (NOW + 999999) + "." + p[2], "user-1", "2026-11-02", NOW));
        assertFalse(TermsCookie.valid("t".repeat(40), cookie, "user-1", "2026-11-02", NOW));
        assertFalse(TermsCookie.valid(SECRET, cookie + "x", "user-1", "2026-11-02", NOW));
    }

    @Test
    void garbage() {
        assertFalse(TermsCookie.valid(SECRET, "nonsense", "user-1", "2026-11-02", NOW));
        assertFalse(TermsCookie.valid(SECRET, "!!.notanumber.x", "user-1", "2026-11-02", NOW));
        assertFalse(TermsCookie.valid(SECRET, null, "user-1", "2026-11-02", NOW));
        assertFalse(TermsCookie.valid(null, cookie, "user-1", "2026-11-02", NOW));
    }
}
