package federation.terms;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Asks the user to agree to the federation's terms, after they have signed in with an
 * identity provider (it runs as that provider's post-broker login flow).
 *
 * <p>Two modes, from the authenticator's configuration:
 * <ul>
 *   <li>{@code every-sign-in} (the default): asked at every sign-in, unless the browser
 *       holds a valid "remember my agreement" cookie that the user chose to have set.</li>
 *   <li>{@code once-per-version}: asked once for each version of the terms. No cookie.</li>
 * </ul>
 * Each agreement is recorded on the user: {@code fed_terms_version} and
 * {@code fed_terms_accepted_at}.
 */
public class TermsAuthenticator implements Authenticator {
    static final String COOKIE = "FED_TERMS";
    static final String ATTR_VERSION = "fed_terms_version";
    static final String ATTR_ACCEPTED_AT = "fed_terms_accepted_at";
    static final String SECRET_ENV = "FED_TERMS_COOKIE_SECRET";

    record Settings(String version, String text, boolean oncePerVersion, int cookieDays, String secret) {
        static Settings of(AuthenticationFlowContext context) {
            AuthenticatorConfigModel model = context.getAuthenticatorConfig();
            Map<String, String> c = model == null || model.getConfig() == null ? Map.of() : model.getConfig();
            String secret = System.getenv(SECRET_ENV);
            int days;
            try {
                days = Integer.parseInt(c.getOrDefault(TermsAuthenticatorFactory.COOKIE_DAYS, "365"));
            } catch (NumberFormatException e) {
                days = 365;
            }
            return new Settings(
                    c.getOrDefault(TermsAuthenticatorFactory.VERSION, "1"),
                    c.getOrDefault(TermsAuthenticatorFactory.TEXT, "Try not to break the testbed."),
                    "once-per-version".equals(c.get(TermsAuthenticatorFactory.MODE)),
                    days,
                    secret != null && secret.length() >= 32 ? secret : null);
        }

        /** The cookie is offered only in every-sign-in mode, and only with a secret to sign it. */
        boolean rememberOffered() {
            return !oncePerVersion && secret != null && cookieDays > 0;
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Settings s = Settings.of(context);
        UserModel user = context.getUser();
        if (s.oncePerVersion() && s.version().equals(user.getFirstAttribute(ATTR_VERSION))) {
            context.success();
            return;
        }
        if (s.rememberOffered()) {
            Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get(COOKIE);
            if (cookie != null && TermsCookie.valid(s.secret(), cookie.getValue(), user.getId(),
                    s.version(), Instant.now().getEpochSecond())) {
                context.success();
                return;
            }
        }
        context.challenge(page(context, s, null));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        Settings s = Settings.of(context);
        if (!"POST".equalsIgnoreCase(context.getHttpRequest().getHttpMethod())) {
            // A reload of the page arrives here as a GET: show it again, without an error.
            context.challenge(page(context, s, null));
            return;
        }
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        if (form.containsKey("cancel")) {
            Response refused = context.form()
                    .setError("fedTermsDeclined")
                    .createErrorPage(Response.Status.FORBIDDEN);
            context.failure(AuthenticationFlowError.ACCESS_DENIED, refused);
            return;
        }
        if (!form.containsKey("agree")) {
            context.challenge(page(context, s, "fedTermsTickToContinue"));
            return;
        }
        UserModel user = context.getUser();
        user.setSingleAttribute(ATTR_VERSION, s.version());
        user.setSingleAttribute(ATTR_ACCEPTED_AT, Instant.now().toString());
        if (s.rememberOffered() && form.containsKey("remember")) {
            remember(context, s, user);
        }
        context.success();
    }

    private static Response page(AuthenticationFlowContext context, Settings s, String error) {
        LoginFormsProvider form = context.form()
                .setAttribute("termsText", s.text())
                .setAttribute("termsVersion", s.version())
                .setAttribute("rememberOffered", s.rememberOffered())
                .setAttribute("cookieDays", s.cookieDays());
        if (error != null) {
            form.setError(error);
        }
        return form.createForm("fed-terms.ftl");
    }

    private static void remember(AuthenticationFlowContext context, Settings s, UserModel user) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        long maxAge = s.cookieDays() * 86400L;
        long expires = Instant.now().getEpochSecond() + maxAge;
        boolean https = "https".equalsIgnoreCase(context.getUriInfo().getRequestUri().getScheme());
        NewCookie cookie = new NewCookie.Builder(COOKIE)
                .value(TermsCookie.issue(s.secret(), user.getId(), s.version(), expires))
                .path("/realms/" + realm.getName() + "/")
                .maxAge((int) Math.min(maxAge, Integer.MAX_VALUE))
                .httpOnly(true)
                .secure(https)
                .sameSite(NewCookie.SameSite.LAX)
                .build();
        session.getContext().getHttpResponse().setCookieIfAbsent(cookie);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}
