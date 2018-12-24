using System.Collections;
using System.Collections.Generic;
using UnityEngine.EventSystems;
using System.IO;
using UnityEngine;

public class copyornah : MonoBehaviour
{


    public GameObject menu;
    public GameObject menubutton;
    public GameObject renamepanel;
    public GameObject newpanel;
    public GameObject fielmanager;
    string simplepath = @"/update/selected.simple";
    string simplecopy = @"/update/copyclicked.simple";
    string renamepath = @"/update/renameclicked.simple";
    string newpath = @"/update/newclicked.simple";
    string filepath = @"/update/fileselected.simple";


    //File.Delete((renamepath);


    // Use this for initialization
    void Start () {
		
	}

    public void backonfocus()
    {
        EventSystem.current.SetSelectedGameObject(fielmanager);

    }

    public void openmenu()
    {
        File.Create(simplepath);
        menu.SetActive(true);
        EventSystem.current.SetSelectedGameObject(menubutton);
    }

    public void Back()
    {
        if (!File.Exists(simplecopy))
        {
            menu.SetActive(false);
        }

        EventSystem.current.SetSelectedGameObject(fielmanager);
    }


    // Update is called once per frame
    void Update()
    {

        //if (Input.GetKey("UI_Submit_PC"))
           // openmenu();
        
        if (!File.Exists(simplecopy))
        {

            if (Input.GetButton("Triangle"))
                openmenu();
        }


        if (Input.GetButton("Cancel"))
        {
            Back();

            if (File.Exists(renamepath))
            {
                File.Delete(renamepath);
            }
            if (File.Exists(simplepath))
            {
                File.Delete(simplepath);
            }
            if (File.Exists(newpath))
            {
                File.Delete(newpath);
            }
            if (File.Exists(filepath))
            {
                File.Delete(filepath);
            }

            renamepanel.SetActive(false);
            newpanel.SetActive(false);
            
        }


    }
}