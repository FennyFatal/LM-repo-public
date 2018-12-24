using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using UnityEngine.EventSystems;
using UnityEngine;

public class copynext : MonoBehaviour {
    [DllImport("HomebrewDump")]
    private static extern void decrypts(char selfFile, char saveFile);


    public GameObject menu;
    public GameObject rootbutton;
    public GameObject menubutton;
    public GameObject menubuttonpaste;
    public GameObject filemanagerbutton;
    string simplepath = @"/update/selected.simple";
    string simplecopy = @"/update/copyclicked.simple";

    [DllImport("HomebrewWIPMsg")]
    private static extern int recoverymsg();


    // Use this for initialization
    void Start () {

        File.Delete(simplecopy);


    }

    public void pasteclicked()
    {
         File.Delete(simplecopy);
        EventSystem.current.SetSelectedGameObject(filemanagerbutton);
        menu.SetActive(false);
    }

    public void hideroot()
    {
        rootbutton.SetActive(false);
        EventSystem.current.SetSelectedGameObject(filemanagerbutton);

    }

    public void copynexts()
    {
         File.Delete(simplepath);
        EventSystem.current.SetSelectedGameObject(filemanagerbutton);
         File.Create(simplecopy);
    }

    // Update is called once per frame
    void Update () {

            if (File.Exists(simplecopy))
        {
            if (Input.GetAxis("_left_trigger") != 0)
                EventSystem.current.SetSelectedGameObject(menubuttonpaste);
        }

    }
}
