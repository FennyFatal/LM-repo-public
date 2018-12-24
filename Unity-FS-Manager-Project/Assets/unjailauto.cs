using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using UnityEngine;

public class unjailauto : MonoBehaviour {

    [DllImport("HomebrewWIP")]
    private static extern int Unjail505();
    string simplepath = @"/update/selected.simple";
    string rwonpath = @"/user/app/NPXX33382/rw_on.txt";
    string pathftp = @"/user/app/NPXX33382/disable_ftp.txt";

    [DllImport("HomebrewWIP")]
    private static extern int FTP();


    [DllImport("HomebrewWIP")]
    private static extern int Mount_RW();

    [DllImport("HomebrewDump")]
    private static extern int loadump();


    [DllImport("HomebrewWIPMsg")]
    private static extern int loadpls();

    [DllImport("HomebrewWIP")]
    private static extern int Off_Mount_RW();

    // Use this for initialization
    void Start()
    {
        loadpls();//
        loadump();
        Unjail505();
    
        File.Create(simplepath);

        if (!File.Exists(pathftp))
        {

            FTP();
        }

        if (!File.Exists(rwonpath))
        {

        }

        else if (File.Exists(rwonpath))
        {

            Mount_RW();

        }

    }
	
	// Update is called once per frame
	void Update () {
		
	}
}
