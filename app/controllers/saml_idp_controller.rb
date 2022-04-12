class SamlIdpController < SamlIdp::IdpController
  before_action :get_relay_state

  def get_relay_state
    session[:RelayState] ||= params[:RelayState]
  end

  def idp_authenticate(email, password)
    email
  end

  def idp_make_saml_response(user)
    encode_SAMLResponse(user, {
      name_id_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:persistent'
    })
  end

  private

  def encode_SAMLResponse(nameID, opts = {})
    now = Time.now.utc
    response_id, reference_id = SecureRandom.uuid, SecureRandom.uuid
    name_id_statement = name_id_attribute(nameID, opts[:name_id_format])
    audience_uri = opts[:audience_uri] || saml_acs_url[/^(.*?\/\/.*?\/)/, 1]
    issuer_uri = opts[:issuer_uri] || (defined?(request) && request.url) || "http://example.com"
    attributes_statement = attributes(opts[:attributes_provider], nameID)

    assertion = %[<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{reference_id}" IssueInstant="#{now.iso8601}" Version="2.0"><saml:Issuer Format="urn:oasis:names:SAML:2.0:nameid-format:entity">#{issuer_uri}</saml:Issuer><saml:Subject>#{name_id_statement}<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData#{@saml_request_id.present? ? %[ InResponseTo="#{@saml_request_id}"] : ""} NotOnOrAfter="#{(now+3*60).iso8601}" Recipient="#{@saml_acs_url}"></saml:SubjectConfirmationData></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="#{(now-5).iso8601}" NotOnOrAfter="#{(now+60*60).iso8601}"><saml:AudienceRestriction><saml:Audience>#{audience_uri}</saml:Audience></saml:AudienceRestriction></saml:Conditions>#{attributes_statement}<saml:AuthnStatement AuthnInstant="#{now.iso8601}" SessionIndex="_#{reference_id}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:federation:authentication:windows</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>]

    digest_value = Base64.encode64(algorithm.digest(assertion)).gsub(/\n/, '')
    # digest_value = assertion

    signed_info = %[<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}"></ds:SignatureMethod><ds:Reference URI="#_#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig##{algorithm_name}"></ds:DigestMethod><ds:DigestValue>#{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>]

    signature_value = sign(signed_info).gsub(/\n/, '')

    signature = %[<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">#{signed_info}<ds:SignatureValue>#{signature_value}</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>#{self.x509_certificate}</ds:X509Certificate></ds:X509Data></KeyInfo></ds:Signature>]

    assertion_and_signature = assertion.sub(/Issuer\>\<saml:Subject/, "Issuer>#{signature}<saml:Subject")

    xml = %[<samlp:Response ID="_#{response_id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{@saml_acs_url}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified"#{@saml_request_id.present? ? %[ InResponseTo="#{@saml_request_id}"] : ""} xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_uri}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>#{assertion_and_signature}</samlp:Response>]

    Base64.encode64(xml)
  end

  def sign(data)
    key = OpenSSL::PKey::RSA.new(self.secret_key)
    Base64.encode64(key.sign(algorithm.new, data))
  end

  def name_id_attribute(nameID, format)
    case format
    when 'urn:oasis:names:tc:SAML:1.1:nameid-format:persistent'
      value = Digest::MD5.hexdigest(nameID)
    when 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
      value = nameID
    end

    "<saml:NameID Format=\"#{format}\">#{value}</saml:NameID>"
  end

  def attributes(provider, nameID)
    provider ? provider : %[<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>#{nameID}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>]
  end

end