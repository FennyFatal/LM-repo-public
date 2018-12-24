using System;
using System.Runtime.InteropServices;
using System.Text;
using UnityEngine;
using UnityEngine.SceneManagement;
using UnityEngine.UI;

class PS4Unjail : MonoBehaviour
{
    public Button unjailButton;

    [DllImport("505Unjail")]
    private static extern int FreeUnjail();

    [DllImport("HomebrewWIP")]
    private static extern int Unjail455();

    [DllImport("505Unjail")]
    private static extern int GetPid();

    [DllImport("505Unjail")]
    private static extern int GetUid();

    public void Unjail()
    {

        unjailButton.interactable = false;
        FreeUnjail();
    }

    public void unjail455()
    {
        Unjail455();
    }

}