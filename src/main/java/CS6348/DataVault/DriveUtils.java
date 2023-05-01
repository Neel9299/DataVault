package CS6348.DataVault;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.FileContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;

import java.io.*;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DriveUtils {

    private static final String APPLICATION_NAME = "CS 6324 Final Project";

    // The file extension of this application:
    public static final String DATA_VAULT_FILE_EXTENSION = "secret";
    private static final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();

    // This is where the login credentials are stored:
    private static final String TOKENS_DIRECTORY_PATH = "tokens";

    // Scopes for OAUTH:
    private static final List<String> SCOPES = Arrays.asList(
            DriveScopes.DRIVE_METADATA_READONLY, DriveScopes.DRIVE_FILE, DriveScopes.DRIVE_READONLY
    );
    private final String credentialsFilePath;

    private final Drive driveService;


    /**
     * If you want to override a file, use this method.
     *
     * @param  credentialsFilePath The path to the credentials file.
     */
    public DriveUtils(String credentialsFilePath) throws IOException, GeneralSecurityException {
        this.credentialsFilePath = credentialsFilePath;

        final NetHttpTransport HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();
        driveService = new Drive.Builder(HTTP_TRANSPORT, JSON_FACTORY, this.getCredentials(HTTP_TRANSPORT))
                .setApplicationName(APPLICATION_NAME)
                .build();
    }

    /**
     * Delete a given file.
     *
     * @param  fileId File ID on Google Drive.
     */
    public void deleteFile(String fileId) throws IOException {
        this.driveService.files().delete(fileId).execute();
    }

    /**
     * Download a file and save it to writeHerePath.
     *
     * @param  fileID File ID on Google Drive.
     * @param  writeHerePath Save the file on this path.
     */
    public void downloadFile(String fileID, String writeHerePath) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        this.driveService.files().get(fileID).executeMediaAndDownloadTo(outputStream);

        FileOutputStream fos = new FileOutputStream(writeHerePath);
        outputStream.writeTo(fos);

        fos.close();
        outputStream.close();

    }

    /**
     * Upload a file.
     *
     * @param  pathOnDisk File ID on Google Drive.
     * @param  nameOnGoogleDrive Name on Google Drive after the upload.
     * @return The ID of the newly uploaded file.
     */
    public String upload(String pathOnDisk, String nameOnGoogleDrive) throws IOException {
        // Create new file:
        File fileMetadata = new File();
        fileMetadata.setName(nameOnGoogleDrive + "." + DATA_VAULT_FILE_EXTENSION);

        // File's content.
        java.io.File filePath = new java.io.File(pathOnDisk);

        // Specify media type and file-path for file.
        FileContent mediaContent = new FileContent("*/*", filePath);

        File file = this.driveService.files().create(fileMetadata, mediaContent)
                .setFields("id")
                .execute();

        return file.getId();
    }

    /**
     * Upload a file.
     *
     * @param  listShared List shared files only, or just the ones in the main drive.
     * @return A list of files.
     */
    public List<File> listFiles(boolean listShared) throws IOException {

        List<File> result = new ArrayList<>();

        // Either list files that are only "shared with me" or the ones in the main folder:
        Drive.Files.List request = this.driveService.files().list().setQ(
                listShared ? "sharedWithMe" : "'root' in parents and trashed=false"
        );

        do {
            try {
                FileList files = request.execute();

                for(File file : files.getFiles()) {
                    // Only add those with the file extension:
                    if(file.getName() != null && file.getName().toLowerCase().endsWith(DATA_VAULT_FILE_EXTENSION)) {
                        result.add(file);
                    }
                }

                // Request all files:
                request.setPageToken(files.getNextPageToken());
            } catch (IOException e) {
                e.printStackTrace();
                request.setPageToken(null);
            }
        } while (request.getPageToken() != null &&
                request.getPageToken().length() > 0);

        return result;
    }

    /**
     * Creates an authorized Credential object.
     *
     * @param HTTP_TRANSPORT The network HTTP Transport.
     * @return An authorized Credential object.
     * @throws IOException If the credentials.json file cannot be found.
     */
    private Credential getCredentials(final NetHttpTransport HTTP_TRANSPORT) throws IOException {
        // Load client secrets.
        InputStream in = new FileInputStream(credentialsFilePath);
        GoogleClientSecrets clientSecrets =
                GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(in));

        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, clientSecrets, SCOPES)
                .setDataStoreFactory(new FileDataStoreFactory(new java.io.File(TOKENS_DIRECTORY_PATH)))
                .setAccessType("offline")
                .build();
        LocalServerReceiver receiver = new LocalServerReceiver.Builder().setPort(8888).build();
        //returns an authorized Credential object.
        return new AuthorizationCodeInstalledApp(flow, receiver).authorize("user");
    }

}
