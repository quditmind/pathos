# Test fixture for the PATHOS graph rules (example code, not executed).
class AccountsController < ApplicationController
  def show
    # ruleid: pathos-graph-ruby-db-activerecord
    @account = Account.find_by(id: params[:id])
    # ok: pathos-graph-ruby-db-activerecord
    File.find(params[:id])
    # ruleid: pathos-graph-ruby-queue-sidekiq
    AuditWorker.perform_async(@account.id)
    # ruleid: pathos-graph-ruby-http-call
    HTTParty.get("https://api.crm.example.net/accounts")
  end
end
