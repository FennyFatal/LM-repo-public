using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using UnityEngine.EventSystems;
using UnityEngine;

public class settings : MonoBehaviour {

    [DllImport("HomebrewWIP")]
    private static extern int Mount_RW();

    [DllImport("HomebrewWIP")]
    private static extern int Off_Mount_RW();

    public GameObject settingss;
    public GameObject buttononeinset;
    public GameObject rwoff;
    public GameObject ftpoff;
    public GameObject ftpon;
    public GameObject ip;
    public GameObject ipon;
    public GameObject ipoff;
    public GameObject decoptin;
    public GameObject decoptout;
    public GameObject clock;
    public GameObject rwon;
    string simplepath = @"/update/selected.simple";
    string optdecrypt = "/user/app/NPXX33382/enable_decryption.txt";
    public GameObject disabled_in_setting;
    string rwonpath = @"/user/app/NPXX33382/rw_on.txt";
    string pathftp = @"/user/app/NPXX33382/disable_ftp.txt";
    string pathip = @"/user/app/NPXX33382/disable_ip.txt";

    public bool rwtoggles = false;

    // Use this for initialization
    void Start () {


    }


    public void hidedisablediset()
    {
        clock.SetActive(false);
        disabled_in_setting.SetActive(false);
    }
	
    public void showsettings()
    {
        hidedisablediset();
        settingss.SetActive(true);
        EventSystem.current.SetSelectedGameObject(buttononeinset);
        File.Create(simplepath);

    }

    public void backselected()
    {

        File.Delete(simplepath);

    }

    public void rwtoggle()
    {

        if (File.Exists(rwonpath))
        {
            rwoff.SetActive(false);
            rwon.SetActive(true);
            File.Delete(rwonpath);
            Off_Mount_RW();

        }

        else if (!File.Exists(rwonpath))
        {
            rwoff.SetActive(true);
            rwon.SetActive(false);
            File.Create(rwonpath);
            Mount_RW();

        }

    }

    public void ftp()
    {

        if (File.Exists(pathftp))
        {
            ftpoff.SetActive(true);
            ftpon.SetActive(false);
            File.Delete(pathftp);

        }

        else if (!File.Exists(pathftp))
        {
            ftpoff.SetActive(false);
            ftpon.SetActive(true);
            File.Create(pathftp);

        }

    }

    public void optdec()
    {

        if (File.Exists(optdecrypt))
        {
            decoptout.SetActive(false);
            decoptin.SetActive(true);
            File.Delete(optdecrypt);

        }

        else if (!File.Exists(optdecrypt))
        {
            decoptout.SetActive(true);
            decoptin.SetActive(false);
            File.Create(optdecrypt);

        }

    }

    public void iptoggle()
    {

        if (File.Exists(pathip))
        {
            ip.SetActive(true);
            ipoff.SetActive(true);
            ipon.SetActive(false);
            File.Delete(pathip);

        }

        else if (!File.Exists(pathip))
        {
            ip.SetActive(false);
            ipoff.SetActive(false);
            ipon.SetActive(true);
            File.Create(pathip);

        }

    }



    // Update is called once per frame
    void Update () {

        if (Input.GetAxisRaw("Right-Dpad") == -1) //left dpad
        {
            settingss.SetActive(false);
        }

        if (File.Exists(optdecrypt))
        {
            decoptout.SetActive(false);
            decoptin.SetActive(true);

        }

        else if (!File.Exists(optdecrypt))
        {
            decoptout.SetActive(true);
            decoptin.SetActive(false);

        }

        if (File.Exists(rwonpath))
        {
            rwoff.SetActive(false);
            rwon.SetActive(true);

        }

        if (!File.Exists(rwonpath))
        {
            rwoff.SetActive(true);
            rwon.SetActive(false);

        }

        if (!File.Exists(pathftp))
        {
            ftpoff.SetActive(true);
            ftpon.SetActive(false);
            File.Delete(pathftp);

        }

        else if (File.Exists(pathftp))
        {
            ftpoff.SetActive(false);
            ftpon.SetActive(true);
            File.Create(pathftp);

        }

        if (File.Exists(pathip))
        {
            ip.SetActive(false);
            ipoff.SetActive(true);
            ipon.SetActive(false);

        }

        else if (!File.Exists(pathip))
        {
            ip.SetActive(true);
            ipoff.SetActive(false);
            ipon.SetActive(true);

        }

    }
}
