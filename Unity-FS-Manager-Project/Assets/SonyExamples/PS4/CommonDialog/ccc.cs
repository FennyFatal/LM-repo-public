using System.Collections;
using System.Collections.Generic;
using UnityEngine.SceneManagement;
using UnityEngine;

public class ccc : MonoBehaviour
{

    // Use this for initialization
    void Start()
    {

    }

    // Update is called once per frame
    void Update()
    {

    }

    public void NextScene()
    {
        SceneManager.LoadScene("SonyPS4CommonDialog");
    }
    public void Quit()
    {
        Application.Quit();
    }
}