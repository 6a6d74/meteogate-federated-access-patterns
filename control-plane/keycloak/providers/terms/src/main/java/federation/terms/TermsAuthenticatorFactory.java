package federation.terms;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class TermsAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "fed-terms";
    static final String VERSION = "terms_version";
    static final String TEXT = "terms_text";
    static final String MODE = "terms_mode";
    static final String COOKIE_DAYS = "cookie_days";

    private static final TermsAuthenticator SINGLETON = new TermsAuthenticator();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Federation terms and conditions";
    }

    @Override
    public String getHelpText() {
        return "Asks the user to agree to the terms after signing in with an identity provider. "
                + "Use it in a post-broker login flow.";
    }

    @Override
    public String getReferenceCategory() {
        return "fed-terms";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty version = new ProviderConfigProperty(VERSION, "Terms version",
                "Change it to ask everyone again.", ProviderConfigProperty.STRING_TYPE, "1");
        ProviderConfigProperty text = new ProviderConfigProperty(TEXT, "Terms text",
                "Shown on the page.", ProviderConfigProperty.STRING_TYPE, "Try not to break the testbed.");
        ProviderConfigProperty mode = new ProviderConfigProperty(MODE, "When to ask",
                "every-sign-in (unless the user chose to be remembered on this browser) or "
                        + "once-per-version.", ProviderConfigProperty.LIST_TYPE, "every-sign-in");
        mode.setOptions(List.of("every-sign-in", "once-per-version"));
        ProviderConfigProperty days = new ProviderConfigProperty(COOKIE_DAYS, "Remember for (days)",
                "How long the optional cookie lasts. 0 offers no cookie.",
                ProviderConfigProperty.STRING_TYPE, "365");
        return List.of(version, text, mode, days);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
