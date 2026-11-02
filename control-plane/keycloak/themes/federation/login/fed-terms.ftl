<#import "template.ftl" as layout>
<#import "field.ftl" as field>
<#import "buttons.ftl" as buttons>
<#-- Shown by the fed-terms authenticator after sign-in. termsText, termsVersion,
     rememberOffered and cookieDays come from it. -->
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("fedTermsTitle")}
    <#elseif section = "form">
    <div class="${properties.kcContentWrapperClass}">
        <p id="fed-terms-text"><strong>${termsText}</strong></p>
        <p class="${properties.kcInputHelperTextItemTextClass!}">${msg("fedTermsVersion", termsVersion)}</p>
    </div>
    <form id="fed-terms-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="POST">
        <@field.checkbox name="agree" label=msg("fedTermsAgree") />
        <#if rememberOffered>
            <@field.checkbox name="remember" label=msg("fedTermsRemember", cookieDays) />
        </#if>
        <@buttons.actionGroup horizontal=true>
            <@buttons.button name="accept" id="fed-terms-accept" label="fedTermsContinue" class=["kcButtonPrimaryClass"]/>
            <@buttons.button name="cancel" id="fed-terms-cancel" label="doCancel" class=["kcButtonSecondaryClass"]/>
        </@buttons.actionGroup>
    </form>
    <p class="${properties.kcInputHelperTextItemTextClass!}" style="margin-top: 1.5rem">
        <#if rememberOffered>${msg("fedTermsCookieNote")} </#if>${msg("fedTermsWithdraw")}
    </p>
    </#if>
</@layout.registrationLayout>
