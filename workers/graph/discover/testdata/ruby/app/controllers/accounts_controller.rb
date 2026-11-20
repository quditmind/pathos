# Example Rails controller (test fixture for pathos-graph; not run).
require_relative "../../lib/account_service"

class AccountsController
  def show
    svc = AccountService.new
    render_account(svc.lookup(1))
  end

  def render_account(a)
    a.to_s
  end
end
