Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Defines the root path route ("/")
  # root "articles#index"

  get '/saml/auth' => 'saml_idp#new'
  post '/saml/auth' => 'saml_idp#create'
end
