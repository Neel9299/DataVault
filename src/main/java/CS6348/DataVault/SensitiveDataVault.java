package CS6348.DataVault;

import com.google.api.services.drive.model.File;

import javax.security.auth.login.CredentialException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SensitiveDataVault {

    // Required to use the Google Drive API:
    public static final String CREDENTIALS_FILE_PATH = "./credentials.json";

    public static final int SHAMIR_N = 3;
    public static final int SHAMIR_T = 2;

    private final DriveUtils driveUtils;
    private final EncUtility encUtility;

    public SensitiveDataVault() throws GeneralSecurityException, IOException {
        this.driveUtils = new DriveUtils(CREDENTIALS_FILE_PATH);
        this.encUtility = new EncUtility();
    }

    /**
     * Returns a list of "Files" which is a Google Drive File object (NOT Java).
     * The files returned will have the .secret extension. You can call file.getId()
     * to get the string ID that is needed for all other function calls.
     *
     * @return      A list of files with a .secret extension.
     */
    public List<File> listNonSharedFiles() throws IOException {
        return this.driveUtils.listFiles(false);
    }

    /**
     * Lists all files that are shared. This is used for Shamir's secret sharing.
     * The files returned will have the .secret extension. You can call file.getId()
     * to get the string ID that is needed for all other function calls.
     *
     * @return      A list of files with a .secret extension.
     */
    public List<File> listSharedFiles() throws IOException {
        return this.driveUtils.listFiles(true);
    }

    /**
     * If you want to override a file, use this method.
     *
     * @param  password The password of the file.
     * @param  fileToReplaceID The file ID that you want to replace.
     * @param  filePath The path to the plaintext file in the format Adithya mentioned.
     * @param  googleDriveFileName The file name that will appear in Google Drive. The extension is automatically added.
     * @return The ID of the newly uploaded file.
     */
    public String replaceFile(String password, String fileToReplaceID, String filePath, String googleDriveFileName) throws Exception {
        this.driveUtils.deleteFile(fileToReplaceID);
        return this.uploadNewFile(password, filePath, googleDriveFileName);
    }

    /**
     * If you want to upload a new file, use this method.
     * Note that Google Drive allows duplicate filenames, so you have to identify by ID.
     *
     * @param  password The password of the file.
     * @param  filePath The path to the plaintext file in the format Adithya mentioned.
     * @param  googleDriveFileName The file name that will appear in Google Drive. The extension is automatically added.
     * @return The ID of the newly uploaded file.
     */
    public String uploadNewFile(String password, String filePath, String googleDriveFileName) throws Exception {
        byte[] fileBytes = encUtility.readBytes(new java.io.File(filePath), 0);
        String stringData = new String(fileBytes, StandardCharsets.UTF_8);

        this.encUtility.formatFile("./enc-temp", stringData, password);

        String fileID = this.driveUtils.upload("./enc-temp", googleDriveFileName);

        java.io.File file = new java.io.File("./enc-temp");
        if(file.exists() && !file.isDirectory()) {
            file.delete();
        }

        return fileID;
    }

    /**
     * Read a tag or the whole file.
     *
     * @param  password The password of the file.
     * @param  fileID The ID of the file in Google Drive.
     * @param  tag The tag name to retrieve. Leave this as a blank string "" if you want everything.
     * @return The tag or entire decrypted file.
     */
    public String read(String password, String fileID, String tag) throws Exception {
        this.downloadFileByID(fileID);
        return this.encUtility.readFile(fileID, password, null, tag);
    }

    /**
     * A private function called to check if a file has been temporarily downloaded.
     *
     * @param  fileID The ID of the file in Google Drive.
     */
    private void downloadFileByID(String fileID) throws IOException {
        java.io.File file = new java.io.File(fileID);

        if(!file.isDirectory() && file.exists()) {
            file.delete();
        }

        this.driveUtils.downloadFile(fileID, "./" + fileID);

        file.deleteOnExit();
    }

    /**
     * Get the secret sharing codes. Keep in mind that the number associated with the code in the map
     * does matter. You need to provide the correct int number associated with the secret part
     * to successfully recover the secret.
     *
     * @param  password The password of the file.
     * @param  fileID The ID of the file in Google Drive.
     * @return A map containing secret numbers (int) and a hex string of the secret part.
     */
    public Map<Integer, String> getSecretSharingCodes(String password, String fileID) throws Exception {

        this.downloadFileByID(fileID);

        ShamirUtils shamirUtils = new ShamirUtils(SHAMIR_N, SHAMIR_T);

        byte[] iv = new byte[16];
        try (RandomAccessFile data = new RandomAccessFile(fileID, "r")) {
            data.readFully(iv);
        }
        catch(IOException e) {
            System.out.println("Could not read IV from the file:");
            e.printStackTrace();
            return null;
        }

        if(!encUtility.verifyPassword("./" + fileID, password)) {
            throw new CredentialException("Incorrect password for file.");
        }

        byte[] secretKey = this.encUtility.getKey(password, iv);

        Map<Integer, byte[]> secrets = shamirUtils.splitSecret(secretKey);
        Map<Integer, String> result = new HashMap<>();
        for(int i : secrets.keySet()) {
            result.put(i, ShamirUtils.bytesToHexString(secrets.get(i)));
        }

        return result;
    }

    /**
     * Read the file given secrets instead of a password.
     * This function is static since loved ones will likely not have access to this Google
     * Drive account, so a file path can be specified instead.
     *
     * @param  secretsMap A map that contains the secret number to secret part hex string.
     * @param  fileID File ID of the encrypted file in Google Drive. Use the listSharedFiles() function.
     * @param  tag The tag name to retrieve. Leave this as a blank string "" if you want everything.
     * @return Decrypted data of the tag or entire file.
     */
    public String readFileWithSharedSecrets(Map<Integer, String> secretsMap, String fileID, String tag) throws Exception {

        this.downloadFileByID(fileID);

        ShamirUtils shamirUtils = new ShamirUtils(SHAMIR_N, SHAMIR_T);

        if(secretsMap.size() < SHAMIR_T) {
            throw new CredentialException("At least " + SHAMIR_T + " secrets are needed to recover the data.");
        }

        // Convert all hex secrets to bytes:
        HashMap<Integer, byte[]> convertedMap = new HashMap<>();
        for(int i : secretsMap.keySet()) {
            convertedMap.put(i, ShamirUtils.stringToBytes(secretsMap.get(i)));
        }

        // Recover the secret:
        byte[] recoveredSecret = shamirUtils.recoverSecret(convertedMap);

        // Read the file with the secret:
        EncUtility encUtility1 = new EncUtility();

        return encUtility1.readFile(fileID, null, recoveredSecret, tag);

    }

    /**
     * Delete a file.
     *
     * @param  fileID File ID on Google Drive.
     * @return Decrypted data of the tag or entire file.
     */
    public void deleteFile(String fileID) throws IOException {
        this.driveUtils.deleteFile(fileID);
    }
    
    public String createNewFile(String password, String fileContents, String googleDriveFileName) throws Exception {
       
        this.encUtility.formatFile("./enc-temp", fileContents, password);

        String fileID = this.driveUtils.upload("./enc-temp", googleDriveFileName);

        java.io.File file = new java.io.File("./enc-temp");
        if(file.exists() && !file.isDirectory()) {
            file.delete();
        }

        return fileID;
    }
    
     public String changePassword(String password, String fileToReplaceID, String fileContents, String googleDriveFileName) throws Exception {
        this.driveUtils.deleteFile(fileToReplaceID);
        return this.createNewFile(password, fileContents, googleDriveFileName);
    }
     
     

}
