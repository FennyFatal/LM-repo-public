using System;
using System.Runtime.InteropServices;
using System.Text;
using UnityEngine;
using UnityEngine.SceneManagement;
using UnityEngine.UI;

class UIDCheck : MonoBehaviour
{

    [DllImport("HomebrewWIP")]
    private static extern int GetPid();

    [DllImport("HomebrewWIP")]
    private static extern int GetUid();

    private string infoText;
    private int infoCount = 0;
    int interval = 1;
    float nextTime = 0;

    private Text UID;


    void Start()
    {
        UpdateEverySecond();
    }

    void Update()
    {
       /* if (Time.time >= nextTime)
        {
            Destroy(UID);
            UpdateEverySecond();
            nextTime += interval;
        }*/
    }

    void UpdateEverySecond()
    {
        //infoCount++; private Text UID;
        UID = GetComponent<Text>();
        //System.Console.WriteLine("Jailbreaking");
        UID.text += "UID: " + GetUid();
    }

}

