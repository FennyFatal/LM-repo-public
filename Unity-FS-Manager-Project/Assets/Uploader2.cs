using UnityEngine;
using System.Collections;
using System;
using UnityEngine.UI;
using System;
using System.IO;
using System.Net;
using UnityEngine.PS4;
using System.IO;

public class Uploader2: MonoBehaviour
{
    public string FTPHost = "ftp://ftp.darksoftware.xyz";
    public string FTPUserName = "appdebug@darksoftware.xyz";
    public string FTPPassword = "yourpassword";
    public string FilePath;
    public Text outputText;

    public void Start()
    {
        AddToOutputText(string.Format("IP:  " + Network.player.ipAddress));
    }

    public void UploadFile()

    {
        FilePath = Application.dataPath + "/StreamingAssets/test.txt";


        WebClient client = new System.Net.WebClient();
        Uri uri = new Uri(FTPHost + new FileInfo(FilePath).Name);

        client.UploadProgressChanged += new UploadProgressChangedEventHandler(OnFileUploadProgressChanged);
        client.UploadFileCompleted += new UploadFileCompletedEventHandler(OnFileUploadCompleted);
        client.Credentials = new System.Net.NetworkCredential(FTPUserName, FTPPassword);
        client.UploadFileAsync(uri, "STOR", FilePath);
    }

    void OnFileUploadProgressChanged(object sender, UploadProgressChangedEventArgs e)
    {
        Debug.Log("Uploading Progreess: " + e.ProgressPercentage);
        AddToOutputText(string.Format("Here is the FTP Upload path", FilePath));
    }

    void OnFileUploadCompleted(object sender, UploadFileCompletedEventArgs e)
    {
        Debug.Log("File Uploaded");
    }

    void AddToOutputText(string message)
    {
        outputText.text = message + "\n" + outputText.text;
    }
}