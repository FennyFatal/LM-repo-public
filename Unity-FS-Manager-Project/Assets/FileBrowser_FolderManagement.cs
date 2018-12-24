using UnityEngine;
using UnityEngine.UI;
using System.Collections;
using System.Runtime.InteropServices;
using UnityEngine.EventSystems;
using System.IO;
using System;
//
public class FileBrowser_FolderManagement : MonoBehaviour
{
    public GameObject renameyes;
    public GameObject creatyes;
    public GameObject deleteyes;
    public GameObject fsbutton;
    public GameObject menu;
    string simplepath = @"/update/selected.simple";
    string filepath = @"/update/fileselected.simple";
    public SonyPS4CommonDialog GetResult;

    [DllImport("HomebrewWIPMsg")]
    private static extern int copymsg();

    [DllImport("psxloader")]
    private static extern int psxdevloader();

    [DllImport("HomebrewWIPMsg")]
    private static extern int fsfatalerror();//copyfilez(char* src, char* des)

    [DllImport("HomebrewDump")]
    private static extern int decrypttemps22();

    string renamepath = @"/update/renameclicked.simple";
    string newpath = @"/update/newclicked.simple";

    [DllImport("HomebrewWIPMsg")]
    private static extern int term();

    public void Start()
    {
        string sDecrypt = "/user/app/NPXX33382/tmp/";
        string sDecrypted = "/user/app/NPXX33382/tmp/decrypted/";

        if (Directory.Exists(sDecrypt))
        {

            Directory.Delete(sDecrypt, true);

        }

        Directory.CreateDirectory(sDecrypt);

        if (Directory.Exists(sDecrypted))
        {

            Directory.Delete(sDecrypted, true);

        }

        Directory.CreateDirectory(sDecrypted);

    }

    #region Variables

    [Header("Deletion")]

    public GameObject _tDeleteConfirmScreen;
    public Text _tDeleteConfirmText;

    [Header("Creation")]

    public GameObject _tCreateConfirmScreen;
    public InputField _tCreateName;
    public string _sDefaultDirectoryName = "Untitled";

    [Header("Rename")]

    public GameObject _tRenameConfirmScreen;
    public InputField _tRenameName;

    [Header("Copy,Cut,Paste")]

    public Color _tCutColor;


    // Used for cupy cut, and paste operations

    public void closemenu()
    {
        File.Delete(simplepath);
        menu.SetActive(false);
        EventSystem.current.SetSelectedGameObject(fsbutton);
    }

    private string _sCopyPath;
    private bool _bCut;

    #endregion

    #region Delete

    // If something is selected, show confirmation screen
    public void ConfirmDelete()
    {


        if (FileBrowser_UI.Instance._tLastSelected != null)
        {
            _tDeleteConfirmScreen.SetActive(true);

            _tDeleteConfirmText.text = "Do you really want to delete \"" + FileBrowser_UI.Instance._tLastSelected._sLabel.text + "\" ?";

            EventSystem.current.SetSelectedGameObject(deleteyes);

        }
    }

    // Hide window
    public void CancelDelete()
    {
        _tDeleteConfirmScreen.SetActive(false);
    }

    // Delete file, hide window, and refresh display
    public void DeleteSelected()
    {
        try
        {
            if (File.Exists(FileBrowser_UI.Instance._tCurrentlySelected._sPath))
                File.Delete(FileBrowser_UI.Instance._tCurrentlySelected._sPath);
            else if (Directory.Exists(FileBrowser_UI.Instance._tCurrentlySelected._sPath))
                Directory.Delete(FileBrowser_UI.Instance._tCurrentlySelected._sPath, true);

            _tDeleteConfirmScreen.SetActive(false);
        }
        catch (Exception ex)
        {
            term();

            fsfatalerror();

            string path = @"/user/app/NPXX33382/Error_Log.txt";  // file path
            using (StreamWriter sw = new StreamWriter(path, true))
            {
                sw.Write(string.Format("Message: {0}<br />{1}StackTrace :{2}{1}Date :{3}{1}-----------------------------------------------------------------------------{1}", ex.Message, Environment.NewLine, ex.StackTrace, DateTime.Now.ToString()));

            }
            throw;
        }




        FileBrowser_UI.Instance.Refresh();
    }

    #endregion

    #region Create

    // Show confirmation screen with default directory name
    public void ConfirmCreate()
    {
        File.Create((filepath));
        File.Create((newpath));
        _tCreateConfirmScreen.SetActive(true);
        EventSystem.current.SetSelectedGameObject(creatyes);
        _tCreateName.text = _sDefaultDirectoryName;
    }

    // Hide window
    public void CancelCreate()
    {
        _tCreateConfirmScreen.SetActive(false);
    }

    // Makes sure the name is unique, create the directory, and refresh the UI
    public void CreateDirectory()
    {
        try
        {

            string sPath = FileBrowser_UI.Instance._tCurrentFolder + "/" + _tCreateName.text;
            if (Directory.Exists(sPath))
            {
                for (int i = 0; ; i++)
                {
                    if (!Directory.Exists(sPath + " (" + i + ")"))
                    {
                        sPath += " (" + i + ")";
                        break;
                    }
                }
            }

            Directory.CreateDirectory(sPath);

            _tCreateConfirmScreen.SetActive(false);
        }
        catch (Exception ex)
        {
            term();

            fsfatalerror();

            string path = @"/user/app/NPXX33382/Error_Log.txt";  // file path
            using (StreamWriter sw = new StreamWriter(path, true))
            {
                sw.Write(string.Format("Message: {0}<br />{1}StackTrace :{2}{1}Date :{3}{1}-----------------------------------------------------------------------------{1}", ex.Message, Environment.NewLine, ex.StackTrace, DateTime.Now.ToString()));

            }
            throw;
        }



        FileBrowser_UI.Instance.Refresh();
    }

    public void CreateFile()
    {
        try
        {

            string sPath = FileBrowser_UI.Instance._tCurrentFolder + "/" + _tCreateName.text;
            if (File.Exists(sPath))
            {
                for (int i = 0; ; i++)
                {
                    if (!File.Exists(sPath + " (" + i + ")"))
                    {
                        sPath += " (" + i + ")";
                        break;
                    }
                }
            }

            File.Create(sPath);

            _tCreateConfirmScreen.SetActive(false);
        }
        catch (Exception ex)
        {
            term();

            fsfatalerror();

            string path = @"/user/app/NPXX33382/Error_Log.txt";  // file path
            using (StreamWriter sw = new StreamWriter(path, true))
            {
                sw.Write(string.Format("Message: {0}<br />{1}StackTrace :{2}{1}Date :{3}{1}-----------------------------------------------------------------------------{1}", ex.Message, Environment.NewLine, ex.StackTrace, DateTime.Now.ToString()));

            }
            throw;
        }



        FileBrowser_UI.Instance.Refresh();
    }


    #endregion

    #region CopyCutPasteELF



    public void liborbiselflaunch()
    {
         string tmp = "/user/app/NPXX33382/tmp/";
        string elfpath = "/data/orbislink/";
        string sPaths = tmp + "/" + new FileInfo(_sCopyPath).Name;

        try
        {
            if (Directory.Exists(elfpath))
            {

                Directory.Delete(elfpath, true);

            }

            Directory.CreateDirectory(elfpath);

            File.Copy(_sCopyPath, sPaths);

            File.Move(sPaths, tmp + "/" + "homebrew.elf");

            File.Move(tmp + "/" + "homebrew.elf", elfpath);


            //File.Copy(_sCopyPath, elfpath + "/" + "homebrew.elf");

            psxdevloader();
        }

        catch (Exception ex)
        {
            term();

            fsfatalerror();

            string path = @"/user/app/NPXX33382/Error_Log.txt";  // file path
            using (StreamWriter sw = new StreamWriter(path, true))
            {
                sw.Write(string.Format("Message: {0}<br />{1}StackTrace :{2}{1}Date :{3}{1}-----------------------------------------------------------------------------{1}", ex.Message, Environment.NewLine, ex.StackTrace, DateTime.Now.ToString()));

            }
            throw;
        }
        //
        term();
    }




    // Remember the path of the selected file (it will be lost in the navigation process if not stored)
    public void Copy()
    {
        _sCopyPath = FileBrowser_UI.Instance._tLastSelected._sPath;
        _bCut = false;
    }

    // Same as copy, but also hide the button in the UI
    public void Cut()
    {
        _sCopyPath = FileBrowser_UI.Instance._tCurrentlySelected._sPath;
        _bCut = true;

        FileBrowser_UI.Instance._tCurrentlySelected.GetComponent<Image>().color = _tCutColor;
    }

    public static void Copy(string sourceDirectory, string targetDirectory)
    {
        DirectoryInfo diSource = new DirectoryInfo(sourceDirectory);
        DirectoryInfo diTarget = new DirectoryInfo(targetDirectory);

        CopyAll(diSource, diTarget);
    }

    public static void CopyAll(DirectoryInfo source, DirectoryInfo target)
    {
        Directory.CreateDirectory(target.FullName);

        // Copy each file into the new directory.
        foreach (FileInfo fi in source.GetFiles())
        {
            fi.CopyTo(Path.Combine(target.FullName, fi.Name), true);
        }

        // Copy each subdirectory using recursion.
        foreach (DirectoryInfo diSourceSubDir in source.GetDirectories())
        {
            DirectoryInfo nextTargetSubDir =
                target.CreateSubdirectory(diSourceSubDir.Name);
            CopyAll(diSourceSubDir, nextTargetSubDir);
        }
    }

    public bool IsDirectoryEmpty(string path)
    {
        string[] dirs = System.IO.Directory.GetDirectories(path); string[] files = System.IO.Directory.GetFiles(path);
        return dirs.Length == 0 && files.Length == 0;
    }

    // Copy the file or move it if cut was chosen, and refresh the UI
    public void Paste()
    {
        string sDecrypt = "/user/app/NPXX33382/tmp/";
        string optdecrypt = "/user/app/NPXX33382/enable_decryption.txt";
        string sDecrypted = "/user/app/NPXX33382/tmp/decrypted/";
        //decrypttemps

        try
        {
            copymsg();
            if (File.Exists(_sCopyPath))
            {
                string sPath = FileBrowser_UI.Instance._tCurrentFolder + "/" + new FileInfo(_sCopyPath).Name;

                if (File.Exists(sPath))
                {
                    for (int i = 0; ; i++)
                    {
                        if (!File.Exists(sPath + " (" + i + ")"))
                        {
                            sPath += " (" + i + ")";
                            break;
                        }
                    }
                }

                if (_bCut)

                    File.Move(_sCopyPath, sPath);
                else

                if (File.Exists(optdecrypt))
                {

                    if (Directory.Exists(sDecrypt))
                    {

                        Directory.Delete(sDecrypt, true);

                    }

                    Directory.CreateDirectory(sDecrypt);

                    if (Directory.Exists(sDecrypted))
                    {

                        Directory.Delete(sDecrypted, true);

                    }

                    Directory.CreateDirectory(sDecrypt);

                    Directory.CreateDirectory(sDecrypted);

                    File.Copy(_sCopyPath, sDecrypt + "/" + new FileInfo(_sCopyPath).Name);

                    decrypttemps22();

                    Copy(sDecrypted, sDecrypt);
                    Directory.Delete(sDecrypted, true);
                    Copy(sDecrypt, sPath);


                    if (Directory.Exists(sDecrypt))
                    {

                        Directory.Delete(sDecrypt, true);

                    }
                }
                else
                    File.Copy(_sCopyPath, sPath);

                FileBrowser_UI.Instance.Refresh();
            }



            else if (Directory.Exists(_sCopyPath))
            {
                string sPath = FileBrowser_UI.Instance._tCurrentFolder + "/" + new DirectoryInfo(_sCopyPath).Name;

                if (Directory.Exists(sPath))
                {
                    for (int i = 0; ; i++)
                    {
                        if (!Directory.Exists(sPath + " (" + i + ")"))
                        {
                            sPath += " (" + i + ")";
                            break;
                        }
                    }
                }

                if (_bCut)
                    Directory.Move(_sCopyPath, FileBrowser_UI.Instance._tCurrentFolder + "/" + new DirectoryInfo(_sCopyPath).Name);
                else
                //DirectoryCopy(_sCopyPath, FileBrowser_UI.Instance._tCurrentFolder + "/" + new DirectoryInfo(_sCopyPath).Name);

                if (File.Exists(optdecrypt))
                {

                    if (Directory.Exists(sDecrypt))
                    {

                        Directory.Delete(sDecrypt, true);

                    }

                    Directory.CreateDirectory(sDecrypt);

                    if (Directory.Exists(sDecrypted))
                    {

                        Directory.Delete(sDecrypted, true);

                    }


                    DirectoryCopy(_sCopyPath, sDecrypt + "/" + new DirectoryInfo(_sCopyPath).Name);

                    decrypttemps22();

                    /* if (IsDirectoryEmpty(sDecrypted) == false)
                     {
                         Copy(sDecrypted, sPath);
                         Directory.Delete(sDecrypt, true);

                     }
                     else if (IsDirectoryEmpty(sDecrypted) == true)
                     {
                         Copy(sDecrypt, sPath);
                         Directory.Delete(sDecrypt, true);
                     }*/

                    Copy(sDecrypted, sDecrypt);
                    Directory.Delete(sDecrypted, true);
                    Copy(sDecrypt, sPath);

                    if (Directory.Exists(sDecrypt))
                    {

                        Directory.Delete(sDecrypt, true);

                    }
                }
                else
                    DirectoryCopy(_sCopyPath, FileBrowser_UI.Instance._tCurrentFolder + "/" + new DirectoryInfo(_sCopyPath).Name);


                FileBrowser_UI.Instance.Refresh();
            }

            _sCopyPath = string.Empty;
        }
        catch (Exception ex)
        {
            term();

            fsfatalerror();

            string path = @"/user/app/NPXX33382/Error_Log.txt";  // file path
            using (StreamWriter sw = new StreamWriter(path, true))
            {
                sw.Write(string.Format("Message: {0}<br />{1}StackTrace :{2}{1}Date :{3}{1}-----------------------------------------------------------------------------{1}", ex.Message, Environment.NewLine, ex.StackTrace, DateTime.Now.ToString()));

            }
            throw;
        }

        term();
    }

    private void DirectoryCopy(string sSourceDirName, string sDestDirName)
    {
        // Get the subdirectories for the specified directory.
        DirectoryInfo tDirectory = new DirectoryInfo(sSourceDirName);

        DirectoryInfo[] tDirs = tDirectory.GetDirectories();
        // If the destination directory doesn't exist, create it.
        if (!Directory.Exists(sDestDirName))
        {
            Directory.CreateDirectory(sDestDirName);
        }

        // Get the files in the directory and copy them to the new location.
        FileInfo[] tFiles = tDirectory.GetFiles();
        foreach (FileInfo tFile in tFiles)
        {
            string sTempPath = Path.Combine(sDestDirName, tFile.Name);
          //  StartCoroutine(timecount());
            tFile.CopyTo(sTempPath, false);
        }

        // Copy subdirectories and their contents to new location.
        foreach (DirectoryInfo tSubdir in tDirs)
        {
            string sTempPath = Path.Combine(sDestDirName, tSubdir.Name);
            DirectoryCopy(tSubdir.FullName, sTempPath);
        }
    }

    IEnumerator timecount()
    {
        yield return new WaitForSeconds(1);
    }

    #endregion

    #region Rename

    // Show confirmation screen with current file name
    public void ConfirmRename()
    {
        File.Create(renamepath);
        _tRenameConfirmScreen.SetActive(true);
        // EventSystem.current.SetSelectedGameObject(renameyes);
        EventSystem.current.SetSelectedGameObject(renameyes);
        _tRenameName.text = FileBrowser_UI.Instance._tLastSelected._sLabel.text;
    }

    // Hide window
    public void CancelRename()
    {
        _tRenameConfirmScreen.SetActive(false);
    }

    // Rename folder and refresh UI
    public void RenameDirectory()
    {
        try
        {
            string sPath = FileBrowser_UI.Instance._tLastSelected._sPath;

            if (File.Exists(sPath))
                File.Move(sPath, FileBrowser_UI.Instance._tCurrentFolder + "/" + _tRenameName.text);
            else if (Directory.Exists(sPath))
                Directory.Move(sPath, FileBrowser_UI.Instance._tCurrentFolder + "/" + _tRenameName.text);

            FileBrowser_UI.Instance.Refresh();

            _tRenameConfirmScreen.SetActive(false);
        }
        catch (Exception ex)
        {
            term();

            fsfatalerror();

            string path = @"/user/app/NPXX33382/Error_Log.txt";  // file path
            using (StreamWriter sw = new StreamWriter(path, true))
            {
                sw.Write(string.Format("Message: {0}<br />{1}StackTrace :{2}{1}Date :{3}{1}-----------------------------------------------------------------------------{1}", ex.Message, Environment.NewLine, ex.StackTrace, DateTime.Now.ToString()));

            }
            throw;
        }

    }

    void Update()
    {
        if (File.Exists(renamepath))
        {
            if (Input.GetAxis("_left_trigger") != 0)
            {
                RenameDirectory();
                EventSystem.current.SetSelectedGameObject(fsbutton);
                File.Delete(renamepath);
                closemenu();
            }

        }

        if (File.Exists(newpath))
        {
            if (Input.GetAxis("_left_trigger") != 0)
            {
                CreateDirectory();
                EventSystem.current.SetSelectedGameObject(fsbutton);
                File.Delete(newpath);
                File.Delete(filepath);
                closemenu();
            }

        }

        if (File.Exists(filepath))
        {
            if (Input.GetAxis("Triangle") != 0)
            {
                CreateFile();
                EventSystem.current.SetSelectedGameObject(fsbutton);
                File.Delete(filepath);
                File.Delete(newpath);
                closemenu();
            }

        }
    }

    #endregion
}
