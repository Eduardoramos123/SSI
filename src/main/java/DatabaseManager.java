import javax.lang.model.type.NullType;
import java.sql.*;

public class DatabaseManager {
    private static String DATABASE_URL = null;
    private Connection connection;

    public DatabaseManager(String url) {
        DATABASE_URL = url;
        try {
            connection = DriverManager.getConnection(DATABASE_URL);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public String getSymetricKey(String username) {
        String symetricKey = null;
        try {
            String query = "SELECT SymetricKey FROM User WHERE username = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
                preparedStatement.setString(1, username);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    if (resultSet.next()) {
                        symetricKey = resultSet.getString("SymetricKey");
                    }
                }
            }
        } catch (SQLException e) {
            return "400";
        }

        return symetricKey;
    }

    public String getPublicKey(String username) {
        String publicKey = null;
        try {
            String query = "SELECT PublicKey FROM User WHERE username = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
                preparedStatement.setString(1, username);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    if (resultSet.next()) {
                        publicKey = resultSet.getString("PublicKey");
                    }
                }
            }
        } catch (SQLException e) {
            return "400";
        }

        return publicKey;
    }

    public Integer getPrivilege(String username) {
        Integer privilege = null;
        try {
            String query = "SELECT Privilege FROM User WHERE username = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
                preparedStatement.setString(1, username);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    if (resultSet.next()) {
                        privilege = resultSet.getInt("Privilege");
                    }
                }
            }
        } catch (SQLException e) {
            return 400;
        }

        return privilege;
    }

    public Boolean isFirstTime(String username) {
        Boolean firstTime = false;
        try {
            String query = "SELECT FirstTime FROM User WHERE username = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
                preparedStatement.setString(1, username);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    if (resultSet.next()) {
                        firstTime = resultSet.getBoolean("FirstTime");
                    }
                }
            }
        } catch (SQLException e) {
            return false;
        }

        return firstTime;
    }

    public Boolean addUser(String username, String oneTimeCode) {
        try {
            String query = "INSERT INTO User (username, SymetricKey, PublicKey, Privilege, FirstTime) VALUES (?, ?, ?, ?, ?)";
            try (PreparedStatement preparedStatement = connection.prepareStatement(query)) {
                preparedStatement.setString(1, username);
                preparedStatement.setString(2, oneTimeCode);
                preparedStatement.setString(3, "NULL");
                preparedStatement.setInt(4, 0);
                preparedStatement.setBoolean(5, true);
                preparedStatement.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public Boolean registerUser(String username, String PublicKey) {
        try {
            String updateQuantityQuery = "UPDATE User SET PublicKey = ? WHERE username = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(updateQuantityQuery)) {
                preparedStatement.setString(1, PublicKey);
                preparedStatement.setString(2, username);
                preparedStatement.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public Boolean startSession(String username, String SymetricKey) {
        try {
            String updateQuantityQuery = "UPDATE User SET SymetricKey = ? WHERE username = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(updateQuantityQuery)) {
                preparedStatement.setString(1, SymetricKey);
                preparedStatement.setString(2, username);
                preparedStatement.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public Boolean endSession(String username) {
        try {
            String updateQuantityQuery = "UPDATE User SET SymetricKey = ? WHERE username = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(updateQuantityQuery)) {
                preparedStatement.setString(1, "");
                preparedStatement.setString(2, username);
                preparedStatement.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public Boolean changePrivilege(String username, Integer Privilege) {
        try {
            String updateQuantityQuery = "UPDATE User SET Privilege = ? WHERE username = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(updateQuantityQuery)) {
                preparedStatement.setInt(1, Privilege);
                preparedStatement.setString(2, username);
                preparedStatement.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public Boolean changeFirstTime(String username) {
        try {
            String updateQuantityQuery = "UPDATE User SET FirstTime = ? WHERE username = ?";
            try (PreparedStatement preparedStatement = connection.prepareStatement(updateQuantityQuery)) {
                preparedStatement.setBoolean(1, false);
                preparedStatement.setString(2, username);
                preparedStatement.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public Boolean deleteUser(String username) {
        try {
            String shoppingListProductQuery = "DELETE FROM User WHERE username = ?";
            try (PreparedStatement shoppingListProductStatement = connection.prepareStatement(shoppingListProductQuery)) {
                shoppingListProductStatement.setString(1, username);
                shoppingListProductStatement.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }
}
