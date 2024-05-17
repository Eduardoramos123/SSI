import java.util.Scanner;

public class AdministratorPanel {
    public static DatabaseManager database = new DatabaseManager("jdbc:sqlite:src/main/Database/database_server.db");
    public static CryptoManager cryptoManager = new CryptoManager();
    private static Scanner scanner;

    AdministratorPanel() {
        scanner = new Scanner(System.in);
    }

    public static void menu() {
        System.out.println("\n");
        System.out.println("Administrator Panel:");
        System.out.println("1. Add User");
        System.out.println("2. Remove User");
        System.out.println("3. Change User's Privilege");
        System.out.println("4. Exit");
        System.out.print("Enter your choice: ");
    }

    private static int getUserChoice() {
        return scanner.nextInt();
    }

    private static void addUser(String username) {
        String oneTimeCode = cryptoManager.generateOneTimeCode();
        String sym = cryptoManager.generateSymFromOneTimeCode(oneTimeCode);
        System.out.println("One time code: " + oneTimeCode);
        System.out.println("Symetric Key: " + sym);
        database.addUser(username, sym);
    }

    private static void removeUser(String username) {
        database.deleteUser(username);
    }

    private static void changePrivilege(String username, int priv) {
        database.changePrivilege(username, priv);
    }

    private static void start() {
        while (true) {
            menu();
            int choice = getUserChoice();

            if (choice == 1) {
                System.out.println("Username: ");
                scanner.nextLine();
                String username = scanner.nextLine();

                addUser(username);
                continue;
            }
            else if (choice == 2) {
                System.out.println("Username: ");
                scanner.nextLine();
                String username = scanner.nextLine();

                removeUser(username);
                continue;
            }
            else if (choice == 3) {
                System.out.println("Username: ");
                scanner.nextLine();
                String username = scanner.nextLine();

                System.out.println("Please write a Privilege Level (1-3): ");
                int priv = scanner.nextInt();

                changePrivilege(username, priv);
                continue;
            }
            else if (choice == 4) {
                System.out.println("Goodbye!");
                break;
            }
            else {
                System.out.println("No option with that number.");
                continue;
            }

        }
    }

    public static void main(String[] args) throws Exception {
        AdministratorPanel admin = new AdministratorPanel();
        admin.start();
    }


}
