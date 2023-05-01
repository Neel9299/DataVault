package CS6348.DataVault;

import com.google.api.services.drive.model.File;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Main {
    public static void main(String[] args) {

        MainScreen ms = new MainScreen();
        ms.setVisible(true);
        /*try {
            testing();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }*/

    }

    public static void testing() throws Exception {

        // The only thing you need is an instance of the vault:
        SensitiveDataVault vault = new SensitiveDataVault();

        // Call this function and provide a path
        String exUploadID = vault.uploadNewFile("adithya1234", "./ex.txt", "ex");

        // List all files with the .secret file extension:
        List<File> files = vault.listNonSharedFiles();
        if (files == null || files.isEmpty()) {
            System.out.println("No files found.");
        }
        else {
            System.out.println("Files:");
            for (File file : files) {
                System.out.printf("%s (%s)\n", file.getName(), file.getId());
            }
        }

        // Reading the tags:
        System.out.println(vault.read("adithya1234", exUploadID, ""));
        System.out.println(vault.read("adithya1234", exUploadID, "SSN"));

        // Get secret sharing codes:
        Map<Integer, String> codes = vault.getSecretSharingCodes("adithya1234", exUploadID);
        for(int num : codes.keySet()) {
            System.out.println("Secret #" + num + ": " + codes.get(num));
        }

        // NOTE: This is commented out because you need to edit in order to test it.
        // Reading the files via sharing codes:
        // List all files with the .secret file extension that are in the "shared" directory:
//        List<File> files2 = vault.listSharedFiles();
//        if (files2 == null || files2.isEmpty()) {
//            System.out.println("No files found.");
//        }
//        else {
//            System.out.println("Files:");
//            for (File file : files2) {
//                System.out.printf("%s (%s)\n", file.getName(), file.getId());
//            }
//        }
//
//        // The integers matter. You must put the correct one that corresponds to a specific secret.
//        Map<Integer, String> codes2 = new HashMap<>();
//        codes2.put(1, "PUT CODE 1 HERE");
//        codes2.put(3, "PUT CODE 2 HERE");
//        System.out.println(vault.readFileWithSharedSecrets(codes2, "PUT FILE ID HERE", ""));

        // Testing uploading a second file:
        String newUploadID = vault.uploadNewFile("password123", "./new.txt", "new");

        // Trying to read with an incorrect password:
        try {
            System.out.println(vault.read("adithya1234", newUploadID, ""));
        }
        catch(Exception e) {
            e.printStackTrace();
            System.out.println("Wrong password!");
        }

        System.out.println(vault.read("password123", newUploadID, ""));

        // Delete a file test:
        vault.deleteFile(newUploadID);

        // Testing replace:
        String lastFile = vault.replaceFile("password12345", exUploadID, "./new.txt", "new2");
        System.out.println(vault.read("password12345", lastFile, ""));

    }

}