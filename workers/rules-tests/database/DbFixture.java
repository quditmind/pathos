// Test fixture for workers/rules/pathos-database.yml (Java). Not compiled.
package fixture;

import com.mongodb.BasicDBObject;
import com.mongodb.client.model.Filters;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.persistence.EntityManager;
import org.springframework.jdbc.core.JdbcTemplate;

public class DbFixture {
    // ruleid: pathos.database.connection-string-hardcoded-password
    static final String URL = "jdbc:mysql://app:fixture-jdbc-pass-not-real@db.internal:3306/app";
    // ruleid: pathos.database.connection-string-tls-disabled
    static final String URL2 = "jdbc:mysql://db.internal:3306/app?useSSL=false";
    // ok: pathos.database.connection-string-tls-disabled
    static final String URL3 = "jdbc:postgresql://db.internal:5432/app?sslmode=verify-full";

    ResultSet jdbc(Connection conn, String name) throws Exception {
        Statement st = conn.createStatement();
        // ruleid: pathos.database.java.jdbc-string-building
        ResultSet rs = st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: pathos.database.java.jdbc-string-building
        PreparedStatement ps = conn.prepareStatement("DELETE FROM users WHERE name = '" + name + "'");
        String sql = "UPDATE users SET name = '" + name + "'";
        // ruleid: pathos.database.java.jdbc-string-building
        st.executeUpdate(sql);
        // ok: pathos.database.java.jdbc-string-building
        PreparedStatement ok = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ok.setString(1, name);
        // ok: pathos.database.java.jdbc-string-building
        System.out.println("select " + name);
        return rs;
    }

    void jpa(EntityManager em, JdbcTemplate jt, String id) {
        // ruleid: pathos.database.java.jdbc-string-building
        em.createNativeQuery("SELECT * FROM orders WHERE id = " + id).getResultList();
        // ruleid: pathos.database.java.jdbc-string-building
        jt.queryForList(String.format("SELECT * FROM orders WHERE id = '%s'", id));
        // ok: pathos.database.java.jdbc-string-building
        jt.queryForList("SELECT * FROM orders WHERE id = ?", id);
    }

    void mongo(String expr) {
        // ruleid: pathos.database.java.nosql-injection
        Object a = Filters.where("this.owner == '" + expr + "'");
        // ruleid: pathos.database.java.nosql-injection
        Object b = new BasicDBObject("$where", expr);
        // ok: pathos.database.java.nosql-injection
        Object c = Filters.where("this.active == true");
    }
}
