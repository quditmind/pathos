# Test fixture for the PATHOS graph rules (example code, not executed).
Rails.application.routes.draw do
  # ruleid: pathos-graph-ruby-route
  get "/accounts/:id", to: "accounts#show"
  # ruleid: pathos-graph-ruby-route
  post "/accounts", to: "accounts#create"
end
