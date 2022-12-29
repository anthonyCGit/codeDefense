import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//Salt+Hashing: https://www.baeldung.com/java-password-hashing
//Logging: https://stackoverflow.com/questions/15758685/how-to-write-logs-in-text-file-when-using-java-util-logging-logger

/**
 * A program that safely gathers user input and produces password, output, and log files.
 */
public class DefendJava {

    /**
     * The scanner used to get user input.
     */
    private static final Scanner INPUT_SCANNER = new Scanner(System.in);

    /**
     * The logger used to write to the log file.
     */
    private static final Logger LOGGER = initializeLogger();

    /**
     * Standard error message.
     */
    private static final String ERROR = "Please try again.\n";

    /**
     * Catch block error message.
     */
    private static final String UNEXPECTED_ERROR = "An unexpected error has occurred. Closing...";

    /**
     * Log file save location.
     */
    private static final String LOG_FILE = "logfile.log";

    /**
     * Password file save location.
     */
    private static final String PASS_FILE = "password.txt";

    /**
     * Prompts for, processes, and displays user input.
     * @param args Commandline arguments
     */
    public static void main(String[] args) {
        String firstName;
        String lastName;
        int firstInt;
        int secondInt;
        String inputFilename;
        String outputFilename;
        File inputFile;
        String password;
        byte[] salt;
        byte[] hashedPassword;

        //Begin prompts
        System.out.println("------------ENTER YOUR NAME------------");
        System.out.println("===FIRST NAME===");
        firstName = getName("first");
        System.out.println();
        System.out.println("===LAST NAME===");
        lastName = getName("last");
        System.out.println();

        System.out.println("------------ENTER YOUR INTEGERS------------");
        System.out.println("===FIRST INTEGER===");
        firstInt = getInt("first");
        System.out.println();
        System.out.println("===SECOND INTEGER===");
        secondInt = getInt("second");
        System.out.println();

        System.out.println("------------ENTER YOUR FILES------------");
        //File verification
        System.out.println("===INPUT FILE===");
        inputFilename = "";
        do {
            inputFilename = getFilename("input");
            if (!(new File(inputFilename).exists())) {
                System.out.println("Ensure file exists.");
                System.out.println(ERROR);
            }
        } while (!(new File(inputFilename).exists()));
        inputFile = new File(inputFilename);
        System.out.println();
        System.out.println("===OUTPUT FILE===");
        outputFilename = "";
        do {
            if (inputFilename.equals(outputFilename)) {
                System.out.println("Ensure input and output files are the different.");
                System.out.println(ERROR);
            }
            outputFilename = getFilename("output");
        } while (inputFilename.equals(outputFilename));
        System.out.println();

        System.out.println("------------ENTER YOUR PASSWORD------------");
        System.out.println("===CREATE PASSWORD===");
        password = getPassword();
        salt = generateSalt();
        hashedPassword = generateHashedPassword(password, salt);
        //Password verification failsafe
        if (hashedPassword == null) {
            System.out.println(UNEXPECTED_ERROR);
            LOGGER.info("Null Password");
            System.exit(1);
        }
        createPasswordFile(hashedPassword, salt);
        salt = null;
        hashedPassword = null;
        System.out.println();
        System.out.println("===REENTER PASSWORD===");
        reenterPassword();
        System.out.println();

        System.out.println("------------FILE OUTPUT------------");
        createOutputFile(outputFilename, inputFile, firstName, lastName, firstInt, secondInt);
        INPUT_SCANNER.close();
        System.exit(0);
    }

    /**
     * Initializes the logger to be used.
     * @return The logger to be used.
     */
    private static Logger initializeLogger() {
        Logger logger = Logger.getLogger("logfile");
        FileHandler fh;
        try {
            fh = new FileHandler(LOG_FILE, true);
            logger.addHandler(fh);
            SimpleFormatter formatter = new SimpleFormatter();
            fh.setFormatter(formatter);
            logger.setUseParentHandlers(false);
        } catch (SecurityException | IOException e) {
            System.out.println(UNEXPECTED_ERROR);
            System.exit(1);
        }
        return logger;
    }

    /**
     * Prompts the user for a valid name.
     * @param prompt Text used in "Enter your " + prompt + " name: "
     * @return The name string.
     */
    private static String getName(String prompt) {
        String name = "";
        boolean valid = false;
        while (!valid) {
            System.out.println("Valid name characters are A-Z, a-z, -, and '. Any - or ' must be followed by a letter.");
            System.out.println("The first character must be capitalized while the rest are lower case.");
            System.out.print("Enter your " + prompt + " name: ");
            name = INPUT_SCANNER.nextLine();
            valid = validNameStr(name);
            if (!valid) {
                System.out.println(ERROR);
                LOGGER.info("Invalid Name Entered");
            }
        }
        return name;
    }

    /**
     * Verifies the validity of a name string.
     * Valid name characters are A-Z, a-z, -, and '. Any - or ' must be followed by a letter.
     * The first character must be capitalized while the rest are lower case.
     * @param str The string to verify.
     * @return Whether the string is a valid name.
     */
    private static boolean validNameStr(String str) {
        Pattern pattern = Pattern.compile("^[A-Z][a-z]*(['-][a-z]+)*$");
        Matcher matcher = pattern.matcher(str);
        return matcher.find() && str.length() <= 50 && str.length() >= 1;
    }

    /**
     * Prompts the user for a valid integer.
     * @param prompt Text used in "Enter a " + prompt + " 4-byte integer: "
     * @return The integer.
     */
    private static int getInt(String prompt) {
        int num = 0;
        boolean valid = false;
        while (!valid) {
            System.out.print("Enter a " + prompt + " 4-byte integer: ");
            String numstr = INPUT_SCANNER.nextLine();
            valid = validIntStr(numstr);
            if (!valid) {
                System.out.println(ERROR);
                LOGGER.info("Invalid Integer Entered");
            } else {
                Scanner scanner = new Scanner(numstr);
                num = scanner.nextInt();
                scanner.close();
            }
        }
        return num;
    }

    /**
     * Verifies the validity of an integer as a string.
     * Valid integers are within a standard 4 byte int range.
     * @param str The string to verify.
     * @return Whether the string is a valid integer.
     */
    private static boolean validIntStr(String str) {
        Pattern pattern = Pattern.compile("^(-)?[0-9]+$");
        Matcher matcher = pattern.matcher(str);
        Scanner scanner = new Scanner(str);
        boolean hasInt = scanner.hasNextInt();
        scanner.close();
        return matcher.find() && hasInt;
    }

    /**
     * Prompts the user for a valid integer.
     * @param prompt Text used in "Enter your " + prompt + " file: "
     * @return The filename.
     */
    private static String getFilename(String prompt) {
        String filename = "";
        boolean valid = false;
        while (!valid) {
            System.out.println("Valid filename characters are A-Z, a-z, 0-9, and any of the following: `~!@#$%^&() _=+[]{};',.-");
            System.out.println("Invalid characters: \\/:*?\"<>|");
            System.out.println("The file extension must be \".txt\".");
            System.out.println("Filename must be from 5 to 260 characters.");
            System.out.println("The file must exist in the current directory.");
            System.out.print("Enter your " + prompt + " file: ");
            filename = INPUT_SCANNER.nextLine();
            valid = validFilenameStr(filename);
            if (!valid) {
                System.out.println(ERROR);
                LOGGER.info("Invalid Filename Entered");
            }
        }
        return filename;
    }

    /**
     * Verifies the validity of a filename.
     * Valid filename characters are A-Z, a-z, 0-9, and any of the following: `~!@#$%^&() _=+[]{};',.-
     * The filename must end in .txt
     * @param str The string to verify.
     * @return Whether the string is a valid filename.
     */
    private static boolean validFilenameStr(String str) {
        boolean valid = false;
        Pattern pattern = Pattern.compile("[\\/:*?\\\"<>|]");
        Matcher matcher = pattern.matcher(str);
        if (!matcher.find()) {
            pattern = Pattern.compile("^[A-Za-z0-9`~!@#$%^&()_ =+\\[\\]\\{\\};',.-]+(\\.txt)$");
            matcher = pattern.matcher(str);
            valid = matcher.find();
        }
        return valid && str.length() >= 5 && str.length() <= 260;
    }

    /**
     * Prompts the user for a valid password.
     * @return The password.
     */
    private static String getPassword() {
        String password = "";
        boolean valid = false;
        while (!valid) {
            System.out.println("Valid password characters are A-Z, a-z, 0-9, and any of the following: `~!@#$%^&()_ =+.-");
            System.out.println("It must have: \n" +
                    "- At least one capital letter\n" +
                    "- At least one lower case letter\n" +
                    "- At least one number\n" +
                    "- At least one valid symbol\n" +
                    "- A length from 8 to 50 characters");
            System.out.print("Enter your password: ");
            password = INPUT_SCANNER.nextLine();
            valid = validPasswordStr(password);
            if (!valid) {
                System.out.println(ERROR);
                LOGGER.info("Invalid Password Entered");
            }
        }
        return password;
    }

    /**
     * Verifies the validity of a password.
     * Valid password characters are A-Z, a-z, 0-9, and any of the following: `~!@#$%^&()_ =+.-
     * The password needs at least one capital letter, one lowercase letter, one number, and one valid symbol.
     * The password must be from 8 to 50 characters in length.
     * @param str The string to verify.
     * @return Whether the string is valid password.
     */
    private static boolean validPasswordStr(String str) {
        Pattern pattern = Pattern.compile("^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[`~!@#$%^&()_ =+.-])" +
                "([A-Za-z0-9`~!@#$%^&()_ =+.-]{8,50})$");
        Matcher matcher = pattern.matcher(str);
        return matcher.find();
    }

    /**
     * Generates a new salt to be used in a hash function.
     * @return The salt.
     */
    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Generates an encrypted password using the SHA-512 hashing algorithm and a salt.
     * @param password The password string to hash.
     * @param salt The salt to use.
     * @return The hashed password.
     */
    private static byte[] generateHashedPassword(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt);
            byte[] hashedPassword = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return hashedPassword;
        } catch (NoSuchAlgorithmException e) {
            System.out.println(UNEXPECTED_ERROR);
            LOGGER.info(e.toString());
            System.exit(1);
        }
        return null;
    }

    /**
     * Creates a password file, storing the salt and hashed password.
     * @param hashedPassword The hashed password to store.
     * @param salt The salt to store.
     */
    private static void createPasswordFile(byte[] hashedPassword, byte[] salt) {
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(PASS_FILE));
            bw.write(Base64.getEncoder().encodeToString(salt) + "\n");
            bw.append(Base64.getEncoder().encodeToString(hashedPassword));
            bw.close();
        } catch (IOException e) {
            System.out.println(UNEXPECTED_ERROR);
            LOGGER.info(e.toString());
            System.exit(1);
        }
    }

    /**
     * Gets the stored salt and hashed password from the password file.
     * @return A string array containing [salt, hashedPassword]
     */
    private static String[] getStoredPassword() {
        String[] saltpass = new String[2];
        try {
            Scanner scanner = new Scanner(new File(PASS_FILE));
            int i = 0;
            while (scanner.hasNextLine() && i < 2) {
                saltpass[i] = scanner.nextLine();
                i++;
            }
            if (i != 2) {
                System.out.println(UNEXPECTED_ERROR);
                LOGGER.info("Invalid Password File");
                System.exit(1);
            }
            scanner.close();
        } catch (FileNotFoundException e) {
            System.out.println(UNEXPECTED_ERROR);
            LOGGER.info(e.toString());
            System.exit(1);
        }
        return saltpass;
    }

    /**
     * Prompts the user to reenter and verify their password.
     */
    private static void reenterPassword() {
        String[] saltpass = getStoredPassword();
        String password;
        boolean valid = false;
        while (!valid) {
            System.out.print("Reenter your password: ");
            password = INPUT_SCANNER.nextLine();
            valid = validPasswordStr(password);
            if (!valid) {
                System.out.println(ERROR);
                LOGGER.info("Invalid Password Validation: Format");
            } else {
                byte[] hashedPassword = generateHashedPassword(password, Base64.getDecoder().decode(saltpass[0]));
                valid = Base64.getEncoder().encodeToString(hashedPassword).equals(saltpass[1]);
                if (!valid) {
                    System.out.println(ERROR);
                    LOGGER.info("Invalid Password Validation: Verification");
                }
            }
        }
        System.out.println("Password successfully verified.");
    }

    /**
     * Adds two integers without overflow using BigInteger.
     * @param a The first integer.
     * @param b The second integer.
     * @return The sum of both integers as a BigInteger.
     */
    private static BigInteger addIntegers(int a, int b) {
        return new BigInteger(a + "").add(new BigInteger(b + ""));
    }

    /**
     * Multiplies two integers without overflow using BigInteger.
     * @param a The first integer.
     * @param b The second integer.
     * @return The product of both integers as a BigInteger.
     */
    private static BigInteger multiplyIntegers(int a, int b) {
        return new BigInteger(a + "").multiply(new BigInteger(b + ""));
    }

    /**
     * Creates an output file of a specified name containing the user's first name, last name, 2 integers, integer sum,
     * integer product, and specified input file contents.
     * @param outputFilename The name of the output file to create.
     * @param inputFile The input file to read from.
     * @param firstName The user's first name.
     * @param lastName The user's last name.
     * @param firstInt The first integer.
     * @param secondInt The second integer.
     */
    private static void createOutputFile(String outputFilename, File inputFile, String firstName, String lastName, int firstInt, int secondInt) {
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(outputFilename));
            String str = "First Name: " + firstName + "\n";
            System.out.print(str);
            bw.write(str);

            str = "Last Name: " + lastName + "\n";
            System.out.print(str);
            bw.append(str);

            str = "First Integer: " + firstInt + "\n";
            System.out.print(str);
            bw.append(str);

            str = "Second Integer: " + secondInt + "\n";
            System.out.print(str);
            bw.append(str);

            str = "Sum: " + addIntegers(firstInt, secondInt) + "\n";
            System.out.print(str);
            bw.append(str);

            str = "Product: " + multiplyIntegers(firstInt, secondInt) + "\n";
            System.out.print(str);
            bw.append(str);

            str = "Input File Contents:\n";
            System.out.print(str);
            bw.append(str);

            Scanner scanner = new Scanner(inputFile);
            while (scanner.hasNextLine()) {
                str = scanner.nextLine();
                System.out.print(str + "\n");
                bw.append(str + "\n");
            }
            scanner.close();
            bw.close();
        } catch (IOException e) {
            System.out.println(UNEXPECTED_ERROR);
            LOGGER.info(e.toString());
            System.exit(1);
        }
    }
}
