using System;
using System.Runtime.InteropServices;
using System.Text;
using UnityEngine;
using UnityEngine.SceneManagement;
using UnityEngine.UI;

class PIDCheck : MonoBehaviour
{

    [DllImport("HomebrewWIP")]
    private static extern int GetPid();
    private Text PID;


    void Start()
    {
        UpdateEverySecond();
    }

    void Update()
    {
    }

    void UpdateEverySecond()
    {
        PID = GetComponent<Text>();

        PID.text += "PID " + GetPid();
    }
}
