// Test fixture for workers/rules/pathos-database.yml (C#). Not compiled.
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;

public class DbFixture
{
    // ruleid: pathos.database.connection-string-hardcoded-password
    const string Conn = "Server=db.internal;Database=app;User Id=app;Password=fixture-sql-pass-not-real;";
    // ruleid: pathos.database.connection-string-tls-disabled
    const string Conn2 = "Server=db.internal;Database=app;Integrated Security=true;Encrypt=False;";
    // ok: pathos.database.connection-string-hardcoded-password, pathos.database.connection-string-tls-disabled
    const string Conn3 = "Server=db.internal;Database=app;Integrated Security=true;Encrypt=True;";

    public void Ado(SqlConnection conn, string name)
    {
        // ruleid: pathos.database.csharp.sql-string-building
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", conn);
        // ruleid: pathos.database.csharp.sql-string-building
        cmd.CommandText = $"DELETE FROM Users WHERE Name = '{name}'";
        // ok: pathos.database.csharp.sql-string-building
        var ok = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);
        ok.Parameters.AddWithValue("@name", name);
    }

    public void Ef(AppDbContext db, string name)
    {
        // ruleid: pathos.database.csharp.sql-string-building
        var users = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'").ToList();
        // ok: pathos.database.csharp.sql-string-building
        var users2 = db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}").ToList();
    }
}
