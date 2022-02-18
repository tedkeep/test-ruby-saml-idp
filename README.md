# Test SSO IdP

Super simple IdP app that will say yes to ANY SSO request. Very secure!

Uses postgresql.

The [ruby-saml-idp](https://github.com/lawrencepit/ruby-saml-idp) gem allows for the super simple IdP setup.

Here's an example setup for your service provider application if you're using the [ruby-saml](https://github.com/onelogin/ruby-saml) gem.

```
settings = OneLogin::RubySaml::Settings.new

# SP section
settings.assertion_consumer_service_url = "#{request.protocol}#{request.host_with_port}/saml/consume"
# settings.sp_entity_id                   = "#{request.protocol}#{request.host_with_port}/saml/metadata"

# IdP section
settings.idp_entity_id                  = ENV.fetch('SSO_IDP_ISSUER_URL') {nil}
settings.idp_sso_service_url            = ENV.fetch('SSO_IDP_ENDPOINT') {"http://localhost:3050/saml/auth"}
settings.idp_sso_service_binding        = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" # or :post, :redirect
settings.idp_cert_fingerprint           = ENV.fetch('SSO_IDP_CERT_FINGERPRINT') {"9E:65:2E:03:06:8D:80:F2:86:C7:6C:77:A1:D9:14:97:0A:4D:F4:4D"} # default certicate finger print for ruby-saml-idp gem
settings.idp_cert_fingerprint_algorithm = ENV.fetch('SSO_IDP_CERT_FINGERPRINT_ALGORITHM') {"http://www.w3.org/2000/09/xmldsig#sha1"}


settings.name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
```
