using System.Collections;
using System.IO;
using System.Collections.Generic;
using UnityEngine.EventSystems;
using UnityEngine;

    public class Dropd2 : MonoBehaviour
{
    public RectTransform container;
    public bool isOpen;
    public GameObject Infobk;
    public GameObject spooftarget;
    string simplepath = @"/update/selected.simple";

    // Use this for initialization
    void Start()
    {
        container = transform.Find("holder1").GetComponent<RectTransform>();    // that is the header  button for that column? yes all of the select button is the first button
        isOpen = false;
    }

    public void Enter()
    {
        File.Create(simplepath);
        isOpen = true;
    }

    public void Back()
    {
        File.Delete(simplepath);
        isOpen = false;
        Infobk.SetActive(false);
        spooftarget.SetActive(false);
    }


    // Update is called once per frame
    void Update()
    {

        Vector3 scale = container.localScale;
        scale.y = Mathf.Lerp(scale.y, isOpen ? 1 : 0, Time.deltaTime * 12);
        container.localScale = scale;

        if (Input.GetButton("Cancel"))
        {
            Back();
        }

        if (Input.GetAxisRaw("Right-Dpad") == -1)
        {
            Back();
        }

    }

    public void OnPointerEnter(PointerEventData eventData)
    {
        isOpen = false;
    }

    public void OnPointerExit(PointerEventData eventData)
    {
        isOpen = true;
    }
}