class SamlIdpController < SamlIdp::IdpController
  before_action :get_relay_state

  def get_relay_state
    session[:RelayState] ||= params[:RelayState]
  end

  def idp_authenticate(email, password)
    true
  end

  def idp_make_saml_response(user)
    encode_SAMLResponse("you@example.com")
  end

end