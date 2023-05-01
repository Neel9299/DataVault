/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package CS6348.DataVault;

/**
 *
 * @author neelv
 */
public class FileListItem {
    private String fileName;
    private String fileId;
    
    public FileListItem(String fileName, String fileId) {
        this.fileName = fileName;
        this.fileId = fileId;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public String getFileId() {
        return fileId;
    }
    
    @Override
    public String toString() {
        return fileName;
    }
    
}
