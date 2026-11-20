# Example service (test fixture for pathos-graph; not run).
class AccountService
  def lookup(id)
    normalise(id)
  end

  def normalise(id)
    id.to_i
  end
end
